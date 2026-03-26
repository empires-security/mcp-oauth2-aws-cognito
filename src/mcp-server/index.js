const express = require('express');
const cors = require('cors');
const { createResourceMetadata } = require('./resource-metadata');
const { validateToken } = require('./token-validator');
const { isUrlClientId, resolveClientId } = require('./cimd-validator');
const config = require('../shared/config');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Log MCP-Protocol-Version header if present
app.use((req, res, next) => {
  const mcpVersion = req.headers['mcp-protocol-version'];
  if (mcpVersion) {
    console.log(`MCP-Protocol-Version: ${mcpVersion}`);
  }
  next();
});

// Protected Resource Metadata endpoint
app.get('/.well-known/oauth-protected-resource', (req, res) => {
  const metadata = createResourceMetadata();
  res.json(metadata);
});

// Generic OAuth authorization server metadata endpoint (proxies to Cognito)
app.get('/.well-known/oauth-authorization-server', async (req, res) => {
  try {
    // Proxy request to the actual Cognito authorization server metadata
    const axios = require('axios');
    
    // Cognito uses OpenID Connect configuration, not OAuth authorization server endpoint
    // Convert the configured auth server URL to the correct OpenID configuration endpoint
    let cognitoMetadataUrl = config.cognito.authServerUrl;
    
    // If the configured URL points to oauth-authorization-server, change it to openid-configuration
    if (cognitoMetadataUrl.includes('/.well-known/oauth-authorization-server')) {
      cognitoMetadataUrl = cognitoMetadataUrl.replace('/.well-known/oauth-authorization-server', '/.well-known/openid-configuration');
    }
    // If it doesn't have any well-known endpoint, add the OpenID configuration one
    else if (!cognitoMetadataUrl.includes('/.well-known/')) {
      cognitoMetadataUrl = `${cognitoMetadataUrl}/.well-known/openid-configuration`;
    }
    
    console.log(`Proxying authorization server metadata request to: ${cognitoMetadataUrl}`);
    const response = await axios.get(cognitoMetadataUrl);
    
    // Add registration_endpoint to the metadata for RFC 8414 compliance
    const metadata = response.data;
    metadata.registration_endpoint = process.env.DCR_ENDPOINT;
    
    // Add PKCE support indication if not already present
    // AWS Cognito supports PKCE but doesn't advertise it in metadata
    if (!metadata.code_challenge_methods_supported) {
      metadata.code_challenge_methods_supported = ['S256'];
    }

    // Advertise Client ID Metadata Document support (CIMD)
    // Cognito doesn't natively support CIMD, but the MCP server bridges it
    metadata.client_id_metadata_document_supported = true;

    // Store the original Cognito endpoints for proxying
    app.locals.cognitoAuthorizationEndpoint = metadata.authorization_endpoint;
    app.locals.cognitoTokenEndpoint = metadata.token_endpoint;

    // Override authorization and token endpoints to point to MCP server proxy
    // This allows transparent CIMD handling — clients use standard endpoints,
    // and the proxy bridges URL-based client_ids to Cognito via DCR
    const serverBaseUrl = config.mcpServer.baseUrl;
    metadata.authorization_endpoint = `${serverBaseUrl}/oauth/authorize`;
    metadata.token_endpoint = `${serverBaseUrl}/oauth/token`;

    res.json(metadata);
  } catch (error) {
    console.error('Error proxying authorization server metadata:', error.message);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Unable to retrieve authorization server metadata'
    });
  }
});


// OAuth Authorization Proxy
// Transparently handles URL-based client_ids (CIMD) by resolving them to
// Cognito credentials, then redirects to Cognito's authorization endpoint.
// Non-URL client_ids are passed through unchanged.
app.get('/oauth/authorize', async (req, res) => {
  try {
    const clientId = req.query.client_id;
    const cognitoAuthEndpoint = app.locals.cognitoAuthorizationEndpoint;

    if (!cognitoAuthEndpoint) {
      return res.status(503).json({
        error: 'server_error',
        error_description: 'Authorization server metadata not yet loaded. Try requesting /.well-known/oauth-authorization-server first.'
      });
    }

    // Build the redirect URL starting from Cognito's authorization endpoint
    const authUrl = new URL(cognitoAuthEndpoint);

    // Copy all query parameters
    for (const [key, value] of Object.entries(req.query)) {
      if (key !== 'client_id') {
        authUrl.searchParams.set(key, value);
      }
    }

    if (isUrlClientId(clientId)) {
      // CIMD flow: resolve URL client_id to Cognito credentials
      console.log(`CIMD authorize: resolving URL client_id: ${clientId}`);

      const dcrEndpoint = process.env.DCR_ENDPOINT;
      if (!dcrEndpoint) {
        return res.status(500).json({
          error: 'server_error',
          error_description: 'DCR endpoint not configured'
        });
      }

      const mapping = await resolveClientId(clientId, dcrEndpoint);

      // Use the mapped Cognito client_id
      authUrl.searchParams.set('client_id', mapping.client_id);

      // Validate that the requested redirect_uri is in the metadata's allowed list
      const requestedRedirectUri = req.query.redirect_uri;
      if (requestedRedirectUri && !mapping.redirect_uris.includes(requestedRedirectUri)) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'redirect_uri not registered in client metadata document'
        });
      }
    } else {
      // Non-CIMD: pass through client_id unchanged
      authUrl.searchParams.set('client_id', clientId);
    }

    console.log(`Proxying authorize to: ${authUrl.origin}${authUrl.pathname}`);
    res.redirect(authUrl.toString());
  } catch (error) {
    console.error('Authorization proxy error:', error.message);
    res.status(400).json({
      error: 'invalid_client_metadata',
      error_description: error.message
    });
  }
});

// OAuth Token Proxy
// Transparently handles URL-based client_ids (CIMD) by mapping them to
// Cognito credentials, then forwards the token request to Cognito.
// Non-URL client_ids are passed through unchanged.
app.use('/oauth/token', express.urlencoded({ extended: true }));
app.post('/oauth/token', async (req, res) => {
  try {
    const clientId = req.body.client_id;
    const cognitoTokenEndpoint = app.locals.cognitoTokenEndpoint;

    if (!cognitoTokenEndpoint) {
      return res.status(503).json({
        error: 'server_error',
        error_description: 'Authorization server metadata not yet loaded. Try requesting /.well-known/oauth-authorization-server first.'
      });
    }

    // Build the token request body
    const tokenParams = { ...req.body };

    if (isUrlClientId(clientId)) {
      // CIMD flow: look up the mapped Cognito credentials
      console.log(`CIMD token: mapping URL client_id: ${clientId}`);

      const dcrEndpoint = process.env.DCR_ENDPOINT;
      const mapping = await resolveClientId(clientId, dcrEndpoint);

      // Validate redirect_uri against CIMD metadata (defense-in-depth)
      if (tokenParams.redirect_uri && !mapping.redirect_uris.includes(tokenParams.redirect_uri)) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'redirect_uri not registered in client metadata document'
        });
      }

      // Replace with Cognito credentials
      tokenParams.client_id = mapping.client_id;
      tokenParams.client_secret = mapping.client_secret;
    }

    // Forward to Cognito's token endpoint
    const axios = require('axios');
    const querystring = require('querystring');

    const tokenResponse = await axios.post(
      cognitoTokenEndpoint,
      querystring.stringify(tokenParams),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    res.json(tokenResponse.data);
  } catch (error) {
    console.error('Token proxy error:', error.message);
    if (error.response) {
      // Forward Cognito's error response
      return res.status(error.response.status).json(error.response.data);
    }
    res.status(400).json({
      error: 'invalid_request',
      error_description: error.message
    });
  }
});

// Middleware to validate access tokens
const requireAuth = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).set({
      'WWW-Authenticate': `Bearer resource_metadata="${config.mcpServer.baseUrl}/.well-known/oauth-protected-resource", scope="openid profile email mcp-api/read"`
    }).json({
      error: 'unauthorized',
      error_description: 'Valid bearer token required'
    });
  }
  
  const token = authHeader.split(' ')[1];
  
  try {
    const decodedToken = await validateToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Token validation failed:', error.message);
    return res.status(401).set({
      'WWW-Authenticate': `Bearer resource_metadata="${config.mcpServer.baseUrl}/.well-known/oauth-protected-resource", scope="openid profile email mcp-api/read", error="invalid_token", error_description="${error.message}"`
    }).json({
      error: 'unauthorized',
      error_description: error.message
    });
  }
};

// MCP API endpoints
app.get('/v1/contexts', requireAuth, (req, res) => {
  // This would typically fetch data from a database
  const contexts = [
    {
      id: 'ctx_123456',
      name: 'Default Context',
      created_at: new Date().toISOString()
    }
  ];
  
  res.json(contexts);
});

app.post('/v1/contexts', requireAuth, (req, res) => {
  // Create a new context (in a real app, would save to database)
  const newContext = {
    id: `ctx_${Date.now()}`,
    name: req.body.name || 'New Context',
    created_at: new Date().toISOString()
  };
  
  res.status(201).json(newContext);
});

// Start server
app.listen(PORT, () => {
  console.log(`MCP Server running on port ${PORT}`);
  console.log(`Protected Resource Metadata available at: http://localhost:${PORT}/.well-known/oauth-protected-resource`);
  console.log(`Authorization Server Metadata (includes registration_endpoint): http://localhost:${PORT}/.well-known/oauth-authorization-server`);
});
