const axios = require('axios');

/**
 * Fetch authorization server metadata using spec-compliant well-known endpoint probing.
 * Per MCP spec (2025-11-25), clients MUST try multiple well-known endpoints in priority order.
 * If the URL is already a well-known endpoint, fetch it directly first.
 * @param {string} authServerUrl - The authorization server URL from PRM
 * @returns {Promise<Object>} The authorization server metadata
 */
async function fetchAuthServerMetadata(authServerUrl) {
  const parsed = new URL(authServerUrl);

  // If the PRM already gave us a well-known URL, try it directly first
  if (parsed.pathname.includes('/.well-known/')) {
    try {
      console.log(`Fetching auth server metadata from well-known URL: ${authServerUrl}`);
      const response = await axios.get(authServerUrl);
      return response.data;
    } catch (err) {
      console.log(`Direct well-known fetch failed: ${err.message}, falling back to probing`);
    }
  }

  // Extract issuer components for probing
  const origin = parsed.origin;
  const pathComponent = parsed.pathname === '/' ? '' : parsed.pathname;

  // Build ordered list of well-known endpoints to try (per MCP spec)
  const endpoints = pathComponent
    ? [
        // With path: try OAuth 2.0 AS Metadata with path insertion first
        `${origin}/.well-known/oauth-authorization-server${pathComponent}`,
        `${origin}/.well-known/openid-configuration${pathComponent}`,
        `${origin}${pathComponent}/.well-known/openid-configuration`
      ]
    : [
        // Without path: simpler probing
        `${origin}/.well-known/oauth-authorization-server`,
        `${origin}/.well-known/openid-configuration`
      ];

  for (const endpoint of endpoints) {
    try {
      console.log(`Probing auth server metadata at: ${endpoint}`);
      const response = await axios.get(endpoint);
      console.log(`Auth server metadata found at: ${endpoint}`);
      return response.data;
    } catch (err) {
      console.log(`Probe failed for ${endpoint}: ${err.message}`);
    }
  }

  throw new Error(`Could not discover authorization server metadata from: ${authServerUrl}`);
}

/**
 * Perform MCP Server discovery with CIMD capability detection
 * @param {string} mcpServerUrl - The URL of the MCP server
 * @returns {Promise<Object>} - Authorization server info with CIMD support flag
 */
async function discovery(mcpServerUrl) {
  try {
    console.log(`Making initial request to MCP server: ${mcpServerUrl}`);

    // Make a request to the MCP server that will return a 401
    await axios.get(`${mcpServerUrl}/v1/contexts`);

    // If we get here, something is wrong - we expected a 401
    throw new Error('Expected 401 response not received from MCP server');
  } catch (error) {
    // Expected 401 error with WWW-Authenticate header
    if (error.response && error.response.status === 401) {
      const wwwAuthHeader = error.response.headers['www-authenticate'];

      if (!wwwAuthHeader) {
        throw new Error('WWW-Authenticate header missing from 401 response');
      }

      console.log('Received WWW-Authenticate header:', wwwAuthHeader);

      // Extract resource_metadata URL from the header
      const resourceMetadataMatch = wwwAuthHeader.match(/resource_metadata="([^"]+)"/);

      if (!resourceMetadataMatch) {
        throw new Error('resource_metadata not found in WWW-Authenticate header');
      }

      const resourceMetadataUrl = resourceMetadataMatch[1];
      const fullResourceMetadataUrl = resourceMetadataUrl.startsWith('http')
        ? resourceMetadataUrl
        : `${mcpServerUrl}${resourceMetadataUrl}`;

      console.log(`Discovered resource metadata URL: ${fullResourceMetadataUrl}`);

      // Fetch the resource metadata
      const resourceMetadataResponse = await axios.get(fullResourceMetadataUrl);
      const resourceMetadata = resourceMetadataResponse.data;

      if (!resourceMetadata.authorization_servers || resourceMetadata.authorization_servers.length === 0) {
        throw new Error('No authorization servers found in resource metadata');
      }

      // Use the first authorization server
      const authServerUrl = resourceMetadata.authorization_servers[0];
      console.log(`Discovered authorization server: ${authServerUrl}`);

      // Fetch the authorization server metadata using spec-compliant well-known probing
      // MCP spec requires trying multiple endpoints in priority order
      const authServerMetadata = await fetchAuthServerMetadata(authServerUrl);

      try {
        // Check for CIMD support
        const cimdSupported = authServerMetadata.client_id_metadata_document_supported === true;
        console.log(`Client ID Metadata Document support: ${cimdSupported}`);

        if (!cimdSupported) {
          throw new Error('Authorization server does not support Client ID Metadata Documents. ' +
            'Check that client_id_metadata_document_supported is advertised in the auth server metadata.');
        }

        console.log('Authorization Server Metadata:', authServerMetadata);

        return {
          resourceMetadata,
          authServerMetadata,
          authServerUrl,
          cimdSupported
        };
      } catch (authServerError) {
        if (authServerError.message.includes('does not support Client ID')) {
          throw authServerError;
        }
        console.error('Error fetching authorization server metadata:', authServerError.message);
        throw new Error(`Failed to fetch authorization server metadata: ${authServerError.message}`);
      }
    } else {
      console.error('Unexpected error during discovery:', error);
      throw new Error(`Unexpected response from MCP server: ${error.message}`);
    }
  }
}

module.exports = {
  discovery
};
