require('dotenv').config();

// Helper function to extract domain prefix
function extractCognitoDomainPrefix(domainUrl) {
  // Remove protocol and .auth.region.amazoncognito.com
  const urlWithoutProtocol = domainUrl.replace(/^https?:\/\//, '');
  const domainPrefix = urlWithoutProtocol.split('.')[0];
  return domainPrefix;
}

module.exports = {
  // MCP Server Configuration
  mcpServer: {
    baseUrl: process.env.MCP_SERVER_URL || 'http://localhost:3001',
  },
  
  // Base URL for the client
  baseUrl: process.env.CLIENT_URL || 'http://localhost:3000',
  
  // Auto Client Base URL
  autoClientBaseUrl: process.env.AUTO_CLIENT_URL || 'http://localhost:3002',
  
  // Dynamic Client Registration endpoint
  dcrEndpoint: process.env.DCR_ENDPOINT || 'https://api-gateway-url/v1/register',

  // AWS Cognito Configuration
  cognito: {
    region: process.env.COGNITO_REGION || 'us-east-1',
    userPoolId: process.env.COGNITO_USER_POOL_ID,
    clientId: process.env.COGNITO_CLIENT_ID,
    
    // Extract domain prefix from full domain URL
    domain: process.env.COGNITO_DOMAIN 
      ? extractCognitoDomainPrefix(process.env.COGNITO_DOMAIN)
      : '',
    
    // Full domain URL
    domainUrl: `https://${process.env.COGNITO_DOMAIN}`,
    
    // Construct the issuer URL
    issuer: process.env.COGNITO_ISSUER || 
      `https://cognito-idp.${process.env.COGNITO_REGION || 'us-east-1'}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}`,
    
    // Construct the full authorization server metadata URL
    authServerUrl: (() => {
      // If COGNITO_AUTH_SERVER_URL is explicitly set, use it
      if (process.env.COGNITO_AUTH_SERVER_URL) {
        return process.env.COGNITO_AUTH_SERVER_URL;
      }
      
      // Construct the URL manually if not set
      const region = process.env.COGNITO_REGION || 'us-east-1';
      const userPoolId = process.env.COGNITO_USER_POOL_ID;
      
      if (!region || !userPoolId) {
        console.warn('Missing Cognito region or user pool ID for constructing auth server URL');
        return '';
      }
      
      return `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/openid-configuration`
    })()
  },
  
  // OAuth Configuration
  oauth: {
    clientId: process.env.OAUTH_CLIENT_ID || process.env.COGNITO_CLIENT_ID,
    clientSecret: process.env.OAUTH_CLIENT_SECRET || process.env.COGNITO_CLIENT_SECRET,
    redirectUri: process.env.OAUTH_REDIRECT_URI || 'http://localhost:3000/callback',
    scope: process.env.OAUTH_SCOPE || 'openid profile email'
  }
};