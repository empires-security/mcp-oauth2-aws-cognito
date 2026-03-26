# MCP + OAuth2.1 + AWS Cognito Example

## Overview

This repository demonstrates how to secure a Model Context Protocol (MCP) server using OAuth 2.1 authorization flows, implemented entirely with Node.js and Express.js. While this example uses AWS Cognito as the backing authorization server, the implementation is **provider-agnostic** and can work with any OAuth 2.1 compliant authorization server.

Based on the MCP Authorization Specification (version 2025-11-25), this project showcases:
- MCP server acting as a **Resource Server** (RS) with generic OAuth endpoints
- Provider-agnostic OAuth 2.1 implementation (example uses AWS Cognito)
- OAuth 2.1 Authorization Code Flow with PKCE and RFC 8707 Resource Indicators
- Protected Resource Metadata (PRM) document discovery
- **Fully dynamic** authorization server metadata discovery
- Dynamic Client Registration (DCR) support
- Client ID Metadata Documents (CIMD) support
- Enhanced security features from MCP 2025-11-25 specification
- Three client implementations:
  - Static client with pre-configured credentials
  - Auto-discovery client with dynamic registration (DCR)
  - Metadata client using Client ID Metadata Documents (CIMD)

## Provider-Agnostic Design

This implementation follows OAuth 2.1 standards to ensure compatibility with any compliant authorization server:
- **MCP Server**: Exposes standard OAuth metadata endpoints and proxies to the backing authorization server
- **Clients**: Discover authorization servers dynamically without hardcoded provider-specific logic
- **Token Validation**: Uses discovered JWKS URIs and issuer information from authorization server metadata
- **Flexible Backend**: While Cognito is used as an example, any OAuth 2.1 server can be substituted

## Understanding the New MCP Authorization Spec

The new MCP Authorization Specification introduces a clean separation between Resource Servers and Authorization Servers, making it easier to integrate with existing identity providers like AWS Cognito, Okta, Auth0, and others.

Key components of the specification:

1. **Protected Resource Metadata (PRM)** document
   - The MCP server serves this document at `/.well-known/oauth-protected-resource`
   - Contains information about authorization servers, supported scopes, etc.
   - Follows RFC9728 (OAuth 2.0 Protected Resource Metadata)

2. **Discovery Process**
   - When a client receives a 401 Unauthorized response, the WWW-Authenticate header contains a pointer to the PRM document
   - Client fetches the PRM document to discover the authorization server URL
   - Client fetches authorization server metadata dynamically from the discovered URL (no hardcoded endpoints)

3. **OAuth 2.1 Authorization**
   - Authorization Code flow with PKCE
   - Bearer token usage for authenticated requests
   - Dynamic token validation using discovered JWKS URIs and issuer information

4. **Client Registration Priority** (MCP 2025-11-25)
   - **Pre-registered** client credentials (if available for the server)
   - **Client ID Metadata Documents** (if authorization server advertises `client_id_metadata_document_supported: true`)
   - **Dynamic Client Registration** (RFC7591 fallback)
   - Prompt user for manual configuration (last resort)

5. **Dynamic Client Registration (DCR)**
   - Allows clients to automatically register with new MCP servers
   - Eliminates the need for manual client registration processes
   - Follows RFC7591 (OAuth 2.0 Dynamic Client Registration Protocol)

6. **Client ID Metadata Documents (CIMD)**
   - Client publishes its OAuth metadata at an HTTPS URL
   - The URL itself becomes the `client_id`
   - Authorization server fetches and validates the metadata document
   - No pre-registration or database storage required
   - Follows [draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document)

This implementation showcases how to apply these concepts in a provider-agnostic way. The example uses AWS Cognito with custom Dynamic Client Registration through API Gateway endpoints and Lambda functions, but the core OAuth flow works with any compliant authorization server.

## Architecture
```
Client → MCP Server → Authorization Server (e.g., AWS Cognito)
        (Resource Server)    (OAuth 2.1 Provider)
```
1. Client sends a request without a token.
2. MCP server responds with 401 Unauthorized + WWW-Authenticate header pointing to PRM metadata.
3. Client retrieves PRM, discovers the Authorization Server URL dynamically.
4. Client fetches authorization server metadata and performs OAuth 2.1 Authorization Code flow (with PKCE).
5. Client obtains an access token and retries request to MCP server.
6. MCP server validates token using dynamically discovered JWKS and grants access to the protected resource.

For detailed overview, see the [Architecture Overview](./docs/architecture-guide.md).

Diagrams:
- [Architecture Diagram](./docs/mcp-oauth-architecture.mermaid)
- [Sequence Diagram](./docs/mcp-oauth-sequence.mermaid)
- [DCR Sequence Diagram](./docs/mcp-oauth-sequence-dcr.mermaid)
- [CIMD Sequence Diagram](./docs/mcp-oauth-sequence-cimd.mermaid)

## Dynamic Client Registration (DCR)

This implementation includes support for OAuth 2.1 Dynamic Client Registration, allowing clients to:

1. Dynamically discover the MCP server and authorization endpoints
2. Register themselves with the authorization server
3. Obtain credentials for the OAuth flow

The DCR flow works as follows:

1. Client discovers the MCP server's protected resource metadata
2. Client discovers the authorization server (Cognito)
3. Client registers with the DCR endpoint in API Gateway
4. Registration creates a Cognito app client and returns credentials
5. Client uses these credentials for the standard OAuth 2.1 flow

**Implementation Note:** AWS Cognito does not natively support Dynamic Client Registration as specified in OAuth 2.0 DCR (RFC7591). This implementation bridges this gap by using:
- API Gateway endpoints to provide the DCR API interface
- Lambda functions to create Cognito app clients programmatically
- DynamoDB to store the registration data

This approach allows us to maintain compliance with the MCP specification's DCR recommendation while leveraging AWS Cognito for robust authentication and authorization.

**Security Note**: This implementation uses anonymous DCR without additional authentication. For production environments, consider adding:
- Rate limiting on registration requests
- Client authentication (mTLS, initial access tokens)
- Approval workflow for new clients
- Limited scope access for dynamically registered clients

See our [DCR Security Recommendations](./docs/dcr-security-recommendations.md) to enhance the security of the registration process.

## Client ID Metadata Documents (CIMD)

The MCP Authorization Specification (2025-11-25) introduced Client ID Metadata Documents as the recommended client registration method. CIMD allows a client to use an HTTPS URL as its `client_id`, with the URL hosting a JSON document describing the client's OAuth metadata.

### How CIMD Works

1. Client publishes a metadata document at a URL (e.g., `http://localhost:3003/client-metadata.json`)
2. During OAuth authorization, the client uses this URL as its `client_id`
3. The authorization server fetches the metadata document from the URL
4. The server validates the document structure and redirect URIs
5. The client proceeds with a standard OAuth 2.1 flow

### CIMD Metadata Document Example

```json
{
  "client_id": "http://localhost:3003/client-metadata.json",
  "redirect_uris": ["http://localhost:3003/callback"],
  "client_name": "MCP CIMD Demo Client",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

### CIMD Authorization Proxy

AWS Cognito does not natively support Client ID Metadata Documents, just as it doesn't natively support DCR. This implementation bridges CIMD transparently through the MCP server's authorization proxy:

- The MCP server advertises `client_id_metadata_document_supported: true` in authorization server metadata
- The MCP server overrides `authorization_endpoint` and `token_endpoint` in metadata to point to itself
- When a client presents a URL-based `client_id`:
  1. The proxy fetches and validates the client's metadata document
  2. Transparently creates a Cognito app client via the existing DCR infrastructure
  3. Forwards the request to Cognito with the mapped credentials
- When a client presents a standard `client_id` (pre-registered or DCR): requests are passed through to Cognito unchanged

The metadata-client has **zero custom code** for CIMD — it simply uses its metadata URL as `client_id` with standard OAuth endpoints, just like any spec-compliant client. All bridging is handled server-side.

### CIMD Security

The authorization proxy includes:
- SSRF protection (blocks private IP ranges, enforces HTTPS in production)
- Strict `client_id` validation (must match the metadata URL exactly)
- Redirect URI validation
- Response size limits (64KB) and fetch timeouts (5s)
- In-memory caching to prevent redundant fetches

**Note**: In development, `http://localhost` URLs are permitted. Production deployments must use HTTPS.

## Quick Start

### Prerequisites
- Node.js 18+ installed
- AWS test account with access to:
    - Cognito for Authorization Server (1 user pool, 2 app clients)
    - API Gateway / Lambda / DynamoDB for DCR and CIMD bridge (2 resources, 2 functions, 1 table)
    - CloudFormation for deploy (1 stack)
- Basic knowledge of OAuth 2.1 flows

### Setup
1. Clone the repository
   ```bash
   git clone https://github.com/empires-security/mcp-oauth2-aws-cognito.git
   cd mcp-oauth2-aws-cognito
   ```

2. Install dependencies for clients and server
   ```bash
   npm run install:all
   ```

3. Deploy AWS resources
   ```bash
   npm run deploy
   ```

4. Review generated `.env` files in:
   - `src/client/.env`
   - `src/auto-client/.env`
   - `src/metadata-client/.env`
   - `src/mcp-server/.env`
   - Compare with `.env.example` files
   - Manually verify/update CLIENT_SECRET if needed

### Running the Application
1. Start all services (server + 3 clients)
   ```bash
   npm run dev
   ```
2. Visit http://localhost:3000 to test the **pre-registered client** OAuth flow

3. Sign Up for a New User
   - Click the "Log in" button
   - Select "Sign up" in the Cognito hosted UI
   - Create a new user account
   - Verify your account by entering the confirmation code sent to your email
   - After successful verification, you'll be redirected back to the application

4. Click the "Fetch MCP Data" button to make an authenticated request to the MCP server

5. Visit http://localhost:3002 to test the **DCR flow** (auto-discovery client with Dynamic Client Registration)

6. Visit http://localhost:3003 to test the **CIMD flow** (Client ID Metadata Document client)

### Cleanup
1. Cleanup AWS resources
   ```bash
   npm run cleanup
   ```

For detailed setup instructions, see the [Setup Guide](./docs/setup-guide.md).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## References

- [Model Context Protocol Authorization Specification (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [OAuth 2.0 Protected Resource Metadata (RFC 9728)](https://datatracker.ietf.org/doc/rfc9728/)
- [OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)](https://datatracker.ietf.org/doc/rfc7591/)
- [OAuth Client ID Metadata Document (Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document)
- [AWS Cognito Developer Guide](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Authors

- **Empires Security Labs** 🚀

