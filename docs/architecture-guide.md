# MCP OAuth 2.1 Provider-Agnostic Architecture Overview

This document explains the architecture of the MCP OAuth 2.1 implementation. While this example uses AWS Cognito as the Authorization Server, the implementation is **provider-agnostic** and works with any OAuth 2.1 compliant authorization server.

## System Architecture

The implementation is based on a clean separation between the MCP server (Resource Server) and the Authorization Server as defined in the latest MCP Authorization specification. The key innovation is that all discovery and validation happens dynamically without hardcoded provider-specific logic.

## Components

### 1. MCP Client (Express.js)

A Node.js Express application that implements:
- **Dynamic** discovery of Authorization Servers through Protected Resource Metadata
- Provider-agnostic OAuth 2.1 Authorization Code flow with PKCE
- Token management (storage, refresh, etc.)
- Authenticated API calls to the MCP server

The client follows this process:
1. Makes initial request to the MCP server
2. Receives 401 with WWW-Authenticate header pointing to resource metadata
3. Fetches resource metadata to discover authorization server URL
4. **Dynamically fetches** authorization server metadata from discovered URL
5. Initiates OAuth flow using discovered endpoints (with PKCE for security)
6. Receives and stores tokens
7. Uses access token for authenticated requests

### 2. MCP Server (Resource Server, Express.js)

Implemented using Express.js:
- Serves the Protected Resource Metadata document at `/.well-known/oauth-protected-resource`
- **Exposes generic OAuth authorization server metadata** at `/.well-known/oauth-authorization-server` (proxies to backing provider)
- **Dynamically validates access tokens** using discovered JWKS URIs and issuer information
- Returns 401 with appropriate WWW-Authenticate header for unauthenticated requests
- Provides MCP API endpoints as protected resources

### 3. Authorization Server (AWS Cognito in this example)

Serves as the OAuth 2.1 Authorization Server (any compliant provider can be used):
- Manages user authentication and authorization
- Issues access tokens and refresh tokens
- Provides JWT tokens with proper claims
- Supports authorization code flow with PKCE
- **Note**: While Cognito is used as an example, any OAuth 2.1 compliant authorization server can be substituted

### 4. Auto-Discovery Client (Express.js)

A variant of the MCP Client that adds:
- Support for OAuth 2.1 Dynamic Client Registration
- **Complete auto-discovery flow** without any pre-configuration
- Registration with DCR endpoint (API Gateway in this example)
- OAuth flow using dynamically obtained credentials
- **Fully provider-agnostic** - works with any OAuth server that supports DCR

### 5. Metadata Client - CIMD (Express.js)

A standard OAuth client that uses Client ID Metadata Documents for identity:
- **Hosts its own metadata document** at `/client-metadata.json`
- Uses the metadata URL as its `client_id` (e.g., `http://localhost:3003/client-metadata.json`)
- Checks for `client_id_metadata_document_supported` in authorization server metadata
- Uses standard `authorization_endpoint` and `token_endpoint` with URL as `client_id`
- **No custom code** — the MCP server's authorization proxy handles CIMD transparently
- Demonstrates the MCP 2025-11-25 recommended client registration method

### 6. Dynamic Client Registration API (API Gateway + Lambda)

Provides the backend for Dynamic Client Registration:
- API Gateway endpoints for registering clients
- Lambda functions to create Cognito app clients
- DynamoDB table for storing registration information
- Serverless architecture for scalable client registration

### Cognito and Dynamic Client Registration

While the MCP specification recommends supporting Dynamic Client Registration (DCR), AWS Cognito does not natively implement the OAuth 2.0 DCR protocol (RFC7591). To address this limitation, our implementation:

1. Deploys a custom DCR endpoint using API Gateway
2. Implements the registration logic using Lambda functions
3. Creates Cognito app clients programmatically via the AWS SDK
4. Stores registration data in DynamoDB for persistence

This architecture allows our solution to offer the seamless client onboarding benefits of DCR while still leveraging Cognito's robust authentication capabilities. In production environments, you might consider adding security mechanisms to this DCR implementation as outlined in our [DCR Security Recommendations](./docs/dcr-security-recommendations.md).


## Authentication Flow

The complete OAuth 2.1 flow in this implementation works as follows:

1. **Initial Request & Discovery**
   - Client makes a request to the MCP server without authentication
   - Server responds with 401 and WWW-Authenticate header
   - Client extracts the resource metadata URL from the header
   - Client fetches the Protected Resource Metadata document
   - Client discovers the authorization server URL from the metadata

2. **Authorization**
   - Client generates PKCE code verifier and challenge
   - Client redirects user to Cognito authorization endpoint
   - User authenticates with Cognito
   - Cognito redirects back to client with authorization code

3. **Token Exchange**
   - Client exchanges authorization code + code verifier for tokens
   - Cognito issues access token, ID token, and refresh token
   - Client stores tokens securely

4. **Authenticated Requests**
   - Client includes access token in Authorization header
   - MCP server validates the token with Cognito
   - If valid, server processes the request and returns protected resources
   - If invalid, server returns 401 with WWW-Authenticate header

5. **Token Refresh**
   - When access token expires, client uses refresh token
   - Client requests new access token from Cognito
   - Client updates stored tokens

## Client ID Metadata Document (CIMD) Flow

The CIMD flow provides a stateless, URL-based client identity mechanism:

1. **Metadata Publishing**
   - Client hosts a JSON metadata document at a URL (e.g., `http://localhost:3003/client-metadata.json`)
   - Document contains: `client_id` (matching the URL), `redirect_uris`, `client_name`, etc.

2. **Discovery with CIMD Check**
   - Client discovers the authorization server via the standard PRM flow
   - Client checks for `client_id_metadata_document_supported: true` in auth server metadata

3. **Standard OAuth Flow with URL client_id**
   - Client redirects to the discovered `authorization_endpoint` using its metadata URL as `client_id`
   - The MCP server's authorization proxy detects the URL-based `client_id`
   - Proxy fetches and validates the metadata document from the client's URL
   - Proxy creates a Cognito app client via existing DCR Lambda infrastructure (cached)
   - Proxy forwards the request to Cognito with mapped credentials
   - User authenticates, Cognito redirects back to client with authorization code

4. **Token Exchange**
   - Client POSTs to the discovered `token_endpoint` using its metadata URL as `client_id`
   - Proxy maps the URL to cached Cognito credentials and forwards to Cognito
   - Client receives tokens — flow is identical to pre-registered and DCR clients from here

### CIMD vs DCR

| Aspect | DCR | CIMD |
|--------|-----|------|
| Client Identity | Server-assigned UUID | Client-published URL |
| Registration | Client POSTs to registration endpoint | Server fetches client's metadata |
| Metadata Updates | Requires re-registration | Updated at the URL (cached) |
| Trust Model | Server trusts registration request | Server validates published metadata |

## Dynamic Client Registration Flow

The Dynamic Client Registration (DCR) process works as follows:

1. **Client Initialization**
   - Auto-client starts without any pre-configured OAuth credentials
   - Only the MCP server URL is known to the client

2. **MCP Server Discovery**
   - Client makes unauthenticated request to MCP server
   - Server responds with 401 and WWW-Authenticate header
   - Client discovers Protected Resource Metadata (PRM)

3. **Authorization Server Discovery**
   - Client extracts authorization server URL from PRM
   - Client fetches OpenID Connect configuration from Cognito

4. **Dynamic Registration**
   - Client sends registration request to DCR endpoint
   - Request includes redirect URIs and desired scopes
   - Lambda function creates new Cognito app client
   - DynamoDB stores the registration details

5. **Credential Management**
   - Registration response includes client_id and client_secret
   - Client stores these credentials in memory/session
   - Credentials are used for standard OAuth authorization flow

6. **Standard OAuth Flow**
   - Using the dynamically obtained credentials, the client
     proceeds with the standard OAuth 2.1 authorization flow


## AWS Resource Configuration

### Cognito User Pool
- User management and authentication
- OAuth app client with authorization code grant
- Domain for hosted UI

### Express.js Server Configuration
- Implements OAuth 2.1 discovery mechanisms
- Serves Protected Resource Metadata
- Validates tokens using Cognito JWT verification

### API Gateway
- Provides REST API for Dynamic Client Registration
- Routes registration requests to Lambda functions
- Enables scalable client registration capability

### Lambda Functions
- Handle client registration requests
- Create Cognito app clients programmatically
- Store registration information in DynamoDB

### DynamoDB
- Stores client registration details
- Provides persistence for DCR relationships
- Enables lookup of client information

## Security Considerations

This implementation follows OAuth 2.1 and MCP security best practices:

1. **PKCE (Proof Key for Code Exchange)**
   - Protects against authorization code interception
   - Required for all authorization code flows

2. **Token Validation**
   - JWT signature verification
   - Audience and issuer validation
   - Expiration checking

3. **HTTPS Only**
   - All endpoints use HTTPS
   - Secure token transmission

4. **Short-lived Tokens**
   - Access tokens have limited lifetime
   - Refresh tokens for obtaining new access tokens

5. **Proper Authorization**
   - Bearer token usage according to RFC6750
   - WWW-Authenticate headers following RFC9728

6. **Dynamic Client Registration Security**
   - This implementation uses anonymous DCR for simplicity
   - Production systems should implement additional security:
     * Initial access tokens for registration authorization
     * Client authentication (mTLS) for secure registration
     * Registration policies and approval workflows
     * Rate limiting to prevent abuse

7. **Client ID Metadata Document Security**
   - SSRF protection when fetching metadata (blocked private IP ranges)
   - HTTPS enforcement in production (HTTP localhost allowed in dev only)
   - Strict `client_id` to URL matching prevents impersonation
   - Response size limits (64KB) and fetch timeouts (5s) prevent abuse
   - Redirect URI validation prevents open-redirect attacks

## Diagrams
- [Architecture Diagram](./mcp-oauth-architecture.mermaid)
- [Sequence Diagram](./mcp-oauth-sequence.mermaid)
