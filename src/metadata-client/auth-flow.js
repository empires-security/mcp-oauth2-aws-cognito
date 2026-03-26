const axios = require('axios');
const crypto = require('crypto');
const querystring = require('querystring');

// Generate a code verifier and challenge for PKCE
function generatePkce() {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  return { codeVerifier, codeChallenge };
}

// Initiate the OAuth authorization flow using metadata URL as client_id
// Returns { authUrl, codeVerifier, state } — caller stores in session
async function initiateAuthFlow(authServerInfo, metadataUrl) {
  const { authServerMetadata } = authServerInfo;

  if (!authServerMetadata.authorization_endpoint) {
    throw new Error('Authorization endpoint not found in server metadata');
  }

  // Generate PKCE values
  const { codeVerifier, codeChallenge } = generatePkce();

  // Generate a random state value for CSRF protection
  const state = crypto.randomBytes(16).toString('hex');

  // Build the authorization URL using standard discovered endpoint
  const authUrl = new URL(authServerMetadata.authorization_endpoint);

  // Use the metadata URL as the client_id — this is the CIMD standard
  const config = require('../shared/config');
  authUrl.searchParams.append('client_id', metadataUrl);
  authUrl.searchParams.append('redirect_uri', `${config.metadataClientBaseUrl}/callback`);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('scope', 'openid profile email');
  authUrl.searchParams.append('state', state);
  authUrl.searchParams.append('code_challenge', codeChallenge);
  authUrl.searchParams.append('code_challenge_method', 'S256');
  // RFC 8707 Resource Indicators
  authUrl.searchParams.append('resource', config.mcpServer.baseUrl);

  return { authUrl: authUrl.toString(), codeVerifier, state };
}

// Handle the callback from the authorization server
async function handleCallback(code, authServerInfo, metadataUrl, codeVerifier) {
  const { authServerMetadata } = authServerInfo;

  if (!authServerMetadata.token_endpoint) {
    throw new Error('Token endpoint not found in server metadata');
  }

  if (!codeVerifier) {
    throw new Error('Code verifier not found — session may have expired');
  }

  const config = require('../shared/config');

  // Exchange code for tokens using standard token endpoint
  // Use the metadata URL as client_id — the proxy handles CIMD resolution
  const tokenResponse = await axios.post(
    authServerMetadata.token_endpoint,
    querystring.stringify({
      grant_type: 'authorization_code',
      client_id: metadataUrl,
      redirect_uri: `${config.metadataClientBaseUrl}/callback`,
      code,
      code_verifier: codeVerifier,
      resource: config.mcpServer.baseUrl
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );

  const tokens = tokenResponse.data;
  if (tokens.expires_in) {
    tokens.expires_at = Date.now() + (tokens.expires_in * 1000);
  }

  return tokens;
}

// Refresh an access token
async function refreshToken(refreshTokenValue, authServerInfo, metadataUrl) {
  const { authServerMetadata } = authServerInfo;

  if (!authServerMetadata.token_endpoint) {
    throw new Error('Token endpoint not found in server metadata');
  }

  const tokenResponse = await axios.post(
    authServerMetadata.token_endpoint,
    querystring.stringify({
      grant_type: 'refresh_token',
      client_id: metadataUrl,
      refresh_token: refreshTokenValue
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );

  const tokens = tokenResponse.data;
  if (tokens.expires_in) {
    tokens.expires_at = Date.now() + (tokens.expires_in * 1000);
  }
  if (!tokens.refresh_token && refreshTokenValue) {
    tokens.refresh_token = refreshTokenValue;
  }

  return tokens;
}

module.exports = {
  initiateAuthFlow,
  handleCallback,
  refreshToken
};
