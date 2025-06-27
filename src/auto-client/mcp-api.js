const axios = require('axios');
const config = require('../shared/config');

async function getMcpData(accessToken) {
  try {
    const response = await axios.get(`${config.mcpServer.baseUrl}/v1/contexts`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'MCP-Protocol-Version': '2025-06-18'
      }
    });
    
    return response.data;
  } catch (error) {
    console.error('Error calling MCP API:', error.message);
    throw error;
  }
}

module.exports = {
  getMcpData
};
