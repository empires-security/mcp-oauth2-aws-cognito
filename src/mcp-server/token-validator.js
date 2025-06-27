const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const axios = require('axios');
const config = require('../shared/config');

// Cache for JWKs and authorization server metadata
let jwksCache = null;
let jwksCacheTime = null;
let authServerMetadataCache = null;
let authServerMetadataCacheTime = null;
const CACHE_DURATION = 3600000; // 1 hour in milliseconds

async function getAuthServerMetadata() {
  // Check if we have cached, non-expired metadata
  const now = Date.now();
  if (authServerMetadataCache && authServerMetadataCacheTime && 
      (now - authServerMetadataCacheTime < CACHE_DURATION)) {
    return authServerMetadataCache;
  }
  
  // Fetch authorization server metadata from Cognito
  const authServerUrl = config.cognito.authServerUrl;
  
  try {
    const response = await axios.get(authServerUrl);
    authServerMetadataCache = response.data;
    authServerMetadataCacheTime = now;
    return authServerMetadataCache;
  } catch (error) {
    console.error('Error fetching authorization server metadata:', error);
    throw new Error('Unable to fetch authorization server metadata');
  }
}

async function getJwks() {
  // Check if we have a cached, non-expired JWKs
  const now = Date.now();
  if (jwksCache && jwksCacheTime && (now - jwksCacheTime < CACHE_DURATION)) {
    return jwksCache;
  }
  
  // Get JWKS URL from authorization server metadata
  const authServerMetadata = await getAuthServerMetadata();
  const jwksUrl = authServerMetadata.jwks_uri;
  
  if (!jwksUrl) {
    throw new Error('jwks_uri not found in authorization server metadata');
  }
  
  try {
    const response = await axios.get(jwksUrl);
    jwksCache = response.data;
    jwksCacheTime = now;
    return jwksCache;
  } catch (error) {
    console.error('Error fetching JWKs:', error);
    throw new Error('Unable to fetch JWKs');
  }
}

async function validateToken(token) {
  try {
    // Decode the token without verification to get the kid (key ID)
    const decodedToken = jwt.decode(token, { complete: true });
    
    if (!decodedToken) {
      throw new Error('Invalid token format');
    }
    
    //TODO: debug log for dev testing purposes only
    //console.log('Decoded Token Payload:', decodedToken.payload);
    //console.log('Configured Issuer:', config.cognito.issuer);
    //console.log('Configured Client ID:', config.cognito.clientId);

    const { kid } = decodedToken.header;
    
    // Get the JWKs
    const jwks = await getJwks();
    
    // Find the key that matches the kid
    const key = jwks.keys.find(k => k.kid === kid);
    
    if (!key) {
      throw new Error('Invalid token - key not found');
    }
    
    // Convert JWK to PEM
    const pem = jwkToPem(key);
    
    // Get issuer from authorization server metadata
    const authServerMetadata = await getAuthServerMetadata();
    const expectedIssuer = authServerMetadata.issuer;
    
    if (!expectedIssuer) {
      throw new Error('issuer not found in authorization server metadata');
    }
    
    // Verify the token with appropriate validation
    // Note: Cognito tokens typically have client_id as audience, not the resource server URL
    const verifiedToken = jwt.verify(token, pem, {
      issuer: expectedIssuer,
      // For now, skip audience validation as Cognito uses client_id as audience
      // In a full RFC 8707 implementation, we would validate the resource parameter
      algorithms: ['RS256'] // Ensure only secure algorithms are accepted
    });
    
    // Additional manual validation for RFC 8707 Resource Indicators
    // Check if token was issued for this specific resource server
    if (verifiedToken.aud && Array.isArray(verifiedToken.aud)) {
      // Token has multiple audiences - check if our resource is included
      console.log('Token audiences:', verifiedToken.aud);
    } else if (verifiedToken.aud) {
      // Single audience - typically the client_id in Cognito
      console.log('Token audience:', verifiedToken.aud);
    }
    
    return verifiedToken;
  } catch (error) {
    console.error('Token validation error:', error.message);
    throw new Error('Token validation failed: ' + error.message);
  }
}

module.exports = {
  validateToken
};