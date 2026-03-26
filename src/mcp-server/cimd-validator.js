const axios = require('axios');
const { URL } = require('url');
const dns = require('dns');
const { promisify } = require('util');

const dnsResolve = promisify(dns.resolve4);

// In-memory cache for validated metadata documents (5 min TTL)
const metadataCache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_RESPONSE_SIZE = 65536; // 64KB
const FETCH_TIMEOUT_MS = 5000;

// Private/reserved IP ranges to block (SSRF protection)
const BLOCKED_IP_RANGES = [
  /^127\./, // Loopback
  /^10\./, // Class A private
  /^172\.(1[6-9]|2[0-9]|3[01])\./, // Class B private
  /^192\.168\./, // Class C private
  /^169\.254\./, // Link-local
  /^0\./, // Current network
  /^::1$/, // IPv6 loopback
  /^fc00:/, // IPv6 unique local
  /^fe80:/, // IPv6 link-local
];

function isBlockedIp(ip) {
  return BLOCKED_IP_RANGES.some(pattern => pattern.test(ip));
}

/**
 * Validate a metadata URL for safety and correctness
 * @param {string} urlString - The metadata URL to validate
 * @returns {URL} The parsed URL object
 * @throws {Error} If the URL is invalid or blocked
 */
async function validateMetadataUrl(urlString) {
  if (!urlString || typeof urlString !== 'string') {
    throw new Error('Metadata URL is required');
  }

  if (urlString.length > 2048) {
    throw new Error('Metadata URL exceeds maximum length of 2048 characters');
  }

  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    throw new Error('Invalid metadata URL format');
  }

  // Must have a path component (not just the domain)
  if (!parsed.pathname || parsed.pathname === '/') {
    throw new Error('Metadata URL must contain a path component');
  }

  // No fragments allowed
  if (parsed.hash) {
    throw new Error('Metadata URL must not contain fragments');
  }

  // No credentials in URL
  if (parsed.username || parsed.password) {
    throw new Error('Metadata URL must not contain credentials');
  }

  // No dot segments in path
  if (/\/(\.\.?)(\/|$)/.test(parsed.pathname)) {
    throw new Error('Metadata URL must not contain dot path segments');
  }

  const isDev = process.env.NODE_ENV !== 'production';
  const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';

  // Enforce HTTPS in production, allow HTTP for localhost in dev
  if (parsed.protocol === 'http:') {
    if (!isDev || !isLocalhost) {
      throw new Error('Metadata URL must use HTTPS scheme (HTTP only allowed for localhost in development)');
    }
  } else if (parsed.protocol !== 'https:') {
    throw new Error('Metadata URL must use HTTPS scheme');
  }

  // SSRF protection: resolve hostname and check IP (skip for localhost in dev)
  if (!isLocalhost) {
    try {
      const addresses = await dnsResolve(parsed.hostname);
      for (const ip of addresses) {
        if (isBlockedIp(ip)) {
          throw new Error('Metadata URL resolves to a blocked IP address');
        }
      }
    } catch (err) {
      if (err.message.includes('blocked IP')) throw err;
      throw new Error(`Cannot resolve metadata URL hostname: ${parsed.hostname}`);
    }
  }

  return parsed;
}

/**
 * Fetch and validate a Client ID Metadata Document
 * @param {string} metadataUrl - The URL to fetch the metadata from
 * @returns {Promise<Object>} The validated metadata document
 */
async function fetchAndValidateMetadata(metadataUrl) {
  // Check cache first
  const cached = metadataCache.get(metadataUrl);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    console.log(`CIMD cache hit for: ${metadataUrl}`);
    return cached.metadata;
  }

  // Validate URL
  await validateMetadataUrl(metadataUrl);

  // Fetch the metadata document
  let response;
  try {
    response = await axios.get(metadataUrl, {
      timeout: FETCH_TIMEOUT_MS,
      maxContentLength: MAX_RESPONSE_SIZE,
      maxRedirects: 2,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'MCP-Server-CIMD-Validator/1.0'
      },
      validateStatus: (status) => status === 200
    });
  } catch (err) {
    if (err.code === 'ECONNABORTED') {
      throw new Error('Metadata document fetch timed out');
    }
    throw new Error(`Failed to fetch metadata document: ${err.message}`);
  }

  const metadata = response.data;

  if (!metadata || typeof metadata !== 'object') {
    throw new Error('Metadata document is not a valid JSON object');
  }

  // Validate required field: client_id must match the URL exactly
  if (!metadata.client_id) {
    throw new Error('Metadata document missing required field: client_id');
  }
  if (metadata.client_id !== metadataUrl) {
    throw new Error(`Metadata client_id "${metadata.client_id}" does not match the document URL "${metadataUrl}"`);
  }

  // Validate required field: client_name (spec MUST include client_id, client_name, redirect_uris)
  if (!metadata.client_name || typeof metadata.client_name !== 'string' || metadata.client_name.trim() === '') {
    throw new Error('Metadata document missing or empty required field: client_name');
  }

  // Validate required field: redirect_uris
  if (!metadata.redirect_uris || !Array.isArray(metadata.redirect_uris) || metadata.redirect_uris.length === 0) {
    throw new Error('Metadata document missing or empty required field: redirect_uris');
  }

  // Validate each redirect_uri is a valid URL
  for (const uri of metadata.redirect_uris) {
    try {
      new URL(uri);
    } catch {
      throw new Error(`Invalid redirect_uri in metadata: ${uri}`);
    }
  }

  // Apply defaults for optional fields
  if (!metadata.grant_types) {
    metadata.grant_types = ['authorization_code'];
  }
  if (!metadata.response_types) {
    metadata.response_types = ['code'];
  }
  if (!metadata.token_endpoint_auth_method) {
    metadata.token_endpoint_auth_method = 'none';
  }

  // Cache the validated metadata
  metadataCache.set(metadataUrl, {
    metadata,
    timestamp: Date.now()
  });

  console.log(`CIMD validated and cached for: ${metadataUrl}`);
  return metadata;
}

// Cache for CIMD client_id URL -> Cognito credentials mapping
const clientMappingCache = new Map();

/**
 * Check if a client_id is a URL (CIMD) vs a plain string (pre-registered/DCR)
 */
function isUrlClientId(clientId) {
  if (!clientId) return false;
  try {
    const parsed = new URL(clientId);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

/**
 * Resolve a URL-based client_id to Cognito credentials via CIMD + DCR bridge.
 * Returns cached mapping if available.
 */
async function resolveClientId(clientIdUrl, dcrEndpoint) {
  // Check mapping cache
  const cached = clientMappingCache.get(clientIdUrl);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    console.log(`CIMD mapping cache hit: ${clientIdUrl} -> ${cached.mapping.client_id}`);
    return cached.mapping;
  }

  // Fetch and validate the metadata document
  const metadata = await fetchAndValidateMetadata(clientIdUrl);

  console.log(`CIMD validated for client: ${metadata.client_name || metadata.client_id}`);

  // Bridge to DCR: register a Cognito client
  const dcrRequest = {
    redirect_uris: metadata.redirect_uris,
    client_name: metadata.client_name || new URL(clientIdUrl).hostname,
    scope: 'openid profile email'
  };

  const dcrResponse = await axios.post(dcrEndpoint, dcrRequest, {
    headers: { 'Content-Type': 'application/json' }
  });

  const mapping = {
    client_id: dcrResponse.data.client_id,
    client_secret: dcrResponse.data.client_secret,
    redirect_uris: metadata.redirect_uris,
    scope: dcrResponse.data.scope || metadata.scope
  };

  // Cache the mapping
  clientMappingCache.set(clientIdUrl, {
    mapping,
    timestamp: Date.now()
  });

  console.log(`CIMD resolved: ${clientIdUrl} -> Cognito client ${mapping.client_id}`);
  return mapping;
}

module.exports = {
  validateMetadataUrl,
  fetchAndValidateMetadata,
  isUrlClientId,
  resolveClientId
};
