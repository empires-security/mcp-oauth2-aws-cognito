const express = require('express');
const session = require('express-session');
const { discovery } = require('./discovery');
const { registerClient, initiateAuthFlow, handleCallback, refreshToken } = require('./auth-flow');
const { getMcpData } = require('./mcp-api');
const config = require('../shared/config');

const app = express();
const PORT = process.env.AUTO_CLIENT_PORT || 3002;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'mcp-oauth-auto-client-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true in production with HTTPS
}));

// Home page
app.get('/', (req, res) => {
  const isAuthenticated = req.session.tokens && req.session.tokens.access_token;
  
  res.send(`
    <h1>MCP OAuth 2.1 Auto-Discovery Client with DCR</h1>
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

// Initiate login with dynamic client registration
app.get('/login', async (req, res) => {
  try {
    // Start the discovery process
    const authServerInfo = await discovery(config.mcpServer.baseUrl);
    
    // Store discovered info in session
    req.session.authServerInfo = authServerInfo;
    
    // Check if we need to dynamically register a client
    if (!req.session.clientInfo) {
      console.log('No client registration found. Initiating dynamic client registration...');
      
      // Register a client using discovered registration_endpoint
      const clientInfo = await registerClient(authServerInfo, authServerInfo.authServerMetadata.registration_endpoint);
      
      // Store client info in session
      req.session.clientInfo = clientInfo;
      console.log('Client registered:', clientInfo.client_id);
    }
    
    // Initiate the authentication flow using the registered client
    const authUrl = await initiateAuthFlow(authServerInfo, req.session.clientInfo);
    
    // Redirect to the authorization server
    res.redirect(authUrl);
  } catch (error) {
    console.error('Error starting auth flow:', error);
    res.status(500).send(`Error starting authentication: ${error.message}`);
  }
});

// OAuth callback handler
app.get('/callback', async (req, res) => {
  const { code } = req.query;
  const { authServerInfo, clientInfo } = req.session;
  
  if (!code || !authServerInfo || !clientInfo) {
    return res.status(400).send('Missing authorization code, server info, or client info');
  }
  
  try {
    // Exchange code for tokens
    const tokens = await handleCallback(code, authServerInfo, clientInfo);
    
    // Store tokens in session
    req.session.tokens = tokens;
    
    // Redirect to home page
    res.redirect('/');
  } catch (error) {
    console.error('Error handling callback:', error);
    res.status(500).send(`Error exchanging code for token: ${error.message}`);
  }
});

// Fetch MCP data
app.get('/mcp-data', async (req, res) => {
  const { tokens, clientInfo, authServerInfo } = req.session;
  
  if (!tokens || !tokens.access_token || !clientInfo || !authServerInfo) {
    return res.redirect('/login');
  }
  
  try {
    // Check if token is expired and refresh if needed
    if (tokens.expires_at && Date.now() > tokens.expires_at) {
      console.log('Access token expired. Refreshing...');
      const newTokens = await refreshToken(tokens.refresh_token, authServerInfo, clientInfo);
      req.session.tokens = newTokens;
    }
    
    // Make API call to MCP server
    const mcpData = await getMcpData(tokens.access_token);
    
    res.send(`
      <h1>MCP Data from Auto-Discovery Client</h1>
      <p><strong>Client ID:</strong> ${clientInfo.client_id}</p>
      <p><strong>Registered At:</strong> ${new Date(clientInfo.client_id_issued_at * 1000).toLocaleString()}</p>
      <pre>${JSON.stringify(mcpData, null, 2)}</pre>
      <a href="/"><button>Back to Home</button></a>
    `);
  } catch (error) {
    console.error('Error fetching MCP data:', error);
    
    if (error.response && error.response.status === 401) {
      // Token is invalid, redirect to login
      return res.redirect('/login');
    }
    
    res.status(500).send(`Error fetching MCP data: ${error.message}`);
  }
});

// Logout
app.get('/logout', (req, res) => {
  // Clear session
  req.session.destroy();
  res.redirect('/');
});

// Display client registration details
app.get('/client-info', (req, res) => {
  const { clientInfo } = req.session;
  
  if (!clientInfo) {
    return res.status(404).send('No client registration found. <a href="/login">Register a client</a>');
  }
  
  res.send(`
    <h1>Registered Client Details</h1>
    <pre>${JSON.stringify(clientInfo, null, 2)}</pre>
    <a href="/"><button>Back to Home</button></a>
  `);
});

// Start server
app.listen(PORT, () => {
  console.log(`MCP Auto-Discovery Client running on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT} to start`);
});
