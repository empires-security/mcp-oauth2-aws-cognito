const express = require('express');
const session = require('express-session');
const { discovery } = require('./discovery');
const { initiateAuthFlow, handleCallback, refreshToken } = require('./auth-flow');
const { getMcpData } = require('./mcp-api');
const config = require('../shared/config');

const app = express();
const PORT = process.env.METADATA_CLIENT_PORT || 3003;
const CLIENT_URL = process.env.METADATA_CLIENT_URL || `http://localhost:${PORT}`;

// The metadata URL is this client's identity (client_id)
const METADATA_URL = `${CLIENT_URL}/client-metadata.json`;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'mcp-oauth-metadata-client-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true in production with HTTPS
}));

// Serve the Client ID Metadata Document
// This URL IS the client_id — the authorization server fetches it to learn about this client
app.get('/client-metadata.json', (req, res) => {
  const metadata = require('./client-metadata.json');
  // Ensure client_id matches the actual serving URL
  metadata.client_id = METADATA_URL;
  metadata.redirect_uris = [`${CLIENT_URL}/callback`];
  metadata.client_uri = CLIENT_URL;
  res.setHeader('Content-Type', 'application/json');
  res.json(metadata);
});

// Home page
app.get('/', (req, res) => {
  const isAuthenticated = req.session.tokens && req.session.tokens.access_token;

  res.send(`
    <h1>MCP OAuth 2.1 Client ID Metadata Document (CIMD) Client</h1>
    <p><strong>Client Identity (Metadata URL):</strong> <a href="${METADATA_URL}">${METADATA_URL}</a></p>
    <p>This client uses a <em>Client ID Metadata Document</em> as its identity.
    Instead of pre-registered credentials or Dynamic Client Registration,
    the client publishes its OAuth metadata at a URL which becomes its <code>client_id</code>.
    The authorization server transparently fetches and validates this document.</p>
    ${isAuthenticated
      ? '<p>Status: Authenticated</p>'
      : '<p>Status: Not authenticated</p>'}
    <div>
      ${isAuthenticated
        ? '<a href="/mcp-data"><button>Fetch MCP Data</button></a>'
        : '<a href="/login"><button>Log in</button></a>'}
      ${isAuthenticated
        ? '<a href="/logout"><button>Log out</button></a>'
        : ''}
    </div>
  `);
});

// Initiate login — standard OAuth flow using metadata URL as client_id
app.get('/login', async (req, res) => {
  try {
    // Discover the MCP server and authorization server
    const authServerInfo = await discovery(config.mcpServer.baseUrl);

    // Store discovered info in session
    req.session.authServerInfo = authServerInfo;

    // Initiate auth flow using metadata URL as client_id
    // No custom registration step — the authorization server handles CIMD transparently
    console.log(`Starting OAuth flow with client_id: ${METADATA_URL}`);
    const { authUrl, codeVerifier, state } = await initiateAuthFlow(authServerInfo, METADATA_URL);

    // Store PKCE and state in session (not global) for concurrent user safety
    req.session.codeVerifier = codeVerifier;
    req.session.authState = state;

    // Redirect to the authorization server
    res.redirect(authUrl);
  } catch (error) {
    console.error('Error starting auth flow:', error);
    res.status(500).send(`Error starting authentication: ${error.message}`);
  }
});

// OAuth callback handler
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  const { authServerInfo, codeVerifier, authState } = req.session;

  if (!code || !authServerInfo) {
    return res.status(400).send('Missing authorization code or server info');
  }

  // Validate state parameter for CSRF protection
  if (!state || state !== authState) {
    return res.status(400).send('Invalid state parameter — possible CSRF attack');
  }

  try {
    const tokens = await handleCallback(code, authServerInfo, METADATA_URL, codeVerifier);
    req.session.tokens = tokens;
    res.redirect('/');
  } catch (error) {
    console.error('Error handling callback:', error);
    res.status(500).send(`Error exchanging code for token: ${error.message}`);
  }
});

// Fetch MCP data
app.get('/mcp-data', async (req, res) => {
  const { tokens, authServerInfo } = req.session;

  if (!tokens || !tokens.access_token || !authServerInfo) {
    return res.redirect('/login');
  }

  try {
    // Check if token is expired and refresh if needed
    if (tokens.expires_at && Date.now() > tokens.expires_at) {
      console.log('Access token expired. Refreshing...');
      const newTokens = await refreshToken(tokens.refresh_token, authServerInfo, METADATA_URL);
      req.session.tokens = newTokens;
    }

    const mcpData = await getMcpData(tokens.access_token);

    res.send(`
      <h1>MCP Data from CIMD Client</h1>
      <p><strong>Client Identity (Metadata URL):</strong> ${METADATA_URL}</p>
      <pre>${JSON.stringify(mcpData, null, 2)}</pre>
      <a href="/"><button>Back to Home</button></a>
    `);
  } catch (error) {
    console.error('Error fetching MCP data:', error);

    if (error.response && error.response.status === 401) {
      return res.redirect('/login');
    }

    res.status(500).send(`Error fetching MCP data: ${error.message}`);
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Start server
app.listen(PORT, () => {
  console.log(`MCP CIMD Client running on port ${PORT}`);
  console.log(`Client ID Metadata Document served at: ${METADATA_URL}`);
  console.log(`Visit http://localhost:${PORT} to start`);
});
