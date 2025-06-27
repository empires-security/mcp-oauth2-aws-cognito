const config = require('../shared/config');

function createResourceMetadata() {
  // Expose generic OAuth authorization server endpoint
  // The server will proxy this to the actual Cognito endpoints
  const genericAuthServerUrl = `${config.mcpServer.baseUrl}/.well-known/oauth-authorization-server`;
  
  return {
    resource: config.mcpServer.baseUrl,
    authorization_servers: [
      genericAuthServerUrl
    ],
    bearer_methods_supported: [
      "header"
    ],
    scopes_supported: [
      "openid",
      "profile", 
      "email",
      "mcp-api/read",
      "mcp-api/write"
    ],
    resource_documentation: `${config.mcpServer.baseUrl}/docs`
  };
}

module.exports = {
  createResourceMetadata
};
