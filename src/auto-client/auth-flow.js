const axios = require('axios');
const crypto = require('crypto');
const querystring = require('querystring');

// Generate a code verifier and challenge for PKCE
function generatePkce() {
  // Generate a random code verifier
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  
  // Generate code challenge using S256 method
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  
  return {
    codeVerifier,
    codeChallenge
  };
}

// Register a client dynamically
async function registerClient(authServerInfo, dcrEndpoint) {
  try {
    console.log('Registering client with DCR endpoint:', dcrEndpoint);
    
    // Create client registration request
    const registrationRequest = {
      redirect_uris: ['http://localhost:3002/callback'],
      client_name: 'mcp-oauth-demo-auto-discovery-client',
      scope: 'openid profile email mcp-api/read'
    };
    
    // Send registration request
    const response = await axios.post(dcrEndpoint, registrationRequest, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    return response.data;
  } catch (error) {
    console.error('Error registering client:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
    }
    throw new Error(`Client registration failed: ${error.message}`);
  }
}

// Initiate the OAuth authorization flow
async function initiateAuthFlow(authServerInfo, clientInfo) {
  const { authServerMetadata } = authServerInfo;
  
  if (!authServerMetadata.authorization_endpoint) {
    throw new Error('Authorization endpoint not found in server metadata');
  }
  
  // Generate PKCE values
  const { codeVerifier, codeChallenge } = generatePkce();
  
  // Store code verifier in memory (in a real app, store per user/session)
  global.codeVerifier = codeVerifier;
  
  // Generate a random state value for CSRF protection
  const state = crypto.randomBytes(16).toString('hex');
  global.authState = state;
  
  // Build the authorization URL
  const authUrl = new URL(authServerMetadata.authorization_endpoint);
  
  // Add query parameters
  authUrl.searchParams.append('client_id', clientInfo.client_id);
  authUrl.searchParams.append('redirect_uri', clientInfo.redirect_uris[0]);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('scope', clientInfo.scope || 'openid profile email');
  authUrl.searchParams.append('state', state);
  authUrl.searchParams.append('code_challenge', codeChallenge);
  authUrl.searchParams.append('code_challenge_method', 'S256');
  // RFC 8707 Resource Indicators - specify intended resource server
  const config = require('../shared/config');
  authUrl.searchParams.append('resource', config.mcpServer.baseUrl);
  
  return authUrl.toString();
}

// Handle the callback from the authorization server
async function handleCallback(code, authServerInfo, clientInfo) {
  const { authServerMetadata } = authServerInfo;
  
  if (!authServerMetadata.token_endpoint) {
    throw new Error('Token endpoint not found in server metadata');
  }
  
  // Get the code verifier from global (in a real app, retrieve from user session)
  const codeVerifier = global.codeVerifier;
  
  if (!codeVerifier) {
    throw new Error('Code verifier not found');
  }
  
  // Exchange the authorization code for tokens
  const config = require('../shared/config');
  const tokenResponse = await axios.post(
    authServerMetadata.token_endpoint,
    querystring.stringify({
      grant_type: 'authorization_code',
      client_id: clientInfo.client_id,
      client_secret: clientInfo.client_secret,
      redirect_uri: clientInfo.redirect_uris[0],
      code,
      code_verifier: codeVerifier,
      // RFC 8707 Resource Indicators - specify intended resource server
      resource: config.mcpServer.baseUrl
    }),
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    }
  );
  
  const tokens = tokenResponse.data;
  
  // Add expiration time if expires_in is provided
  if (tokens.expires_in) {
    tokens.expires_at = Date.now() + (tokens.expires_in * 1000);
  }
  
  return tokens;
}

// Refresh an access token using a refresh token
async function refreshToken(refreshToken, authServerInfo, clientInfo) {
  const { authServerMetadata } = authServerInfo;
  
  if (!authServerMetadata.token_endpoint) {
    throw new Error('Token endpoint not found in server metadata');
  }
  
  // Exchange the refresh token for a new access token
  const tokenResponse = await axios.post(
    authServerMetadata.token_endpoint,
    querystring.stringify({
      grant_type: 'refresh_token',
      client_id: clientInfo.client_id,
      client_secret: clientInfo.client_secret,
      refresh_token: refreshToken
    }),
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    }
  );
  
  const tokens = tokenResponse.data;
  
  // Add expiration time if expires_in is provided
  if (tokens.expires_in) {
    tokens.expires_at = Date.now() + (tokens.expires_in * 1000);
  }
  
  // Keep the refresh token if a new one wasn't provided
  if (!tokens.refresh_token && refreshToken) {
    tokens.refresh_token = refreshToken;
  }
  
  return tokens;
}

module.exports = {
  registerClient,
  initiateAuthFlow,
  handleCallback,
  refreshToken
};