# MCP + OAuth2.1 + AWS Cognito Example

## Overview

This repository demonstrates how to secure a Model Context Protocol (MCP) server using OAuth 2.1 authorization flows, implemented entirely with Node.js and Express.js. While this example uses AWS Cognito as the backing authorization server, the implementation is **provider-agnostic** and can work with any OAuth 2.1 compliant authorization server.

Based on the MCP Authorization Specification (version 2025-06-18), this project showcases:
- MCP server acting as a **Resource Server** (RS) with generic OAuth endpoints
- Provider-agnostic OAuth 2.1 implementation (example uses AWS Cognito)
- OAuth 2.1 Authorization Code Flow with PKCE and RFC 8707 Resource Indicators
- Protected Resource Metadata (PRM) document discovery
- **Fully dynamic** authorization server metadata discovery
- Dynamic Client Registration (DCR) support
- Enhanced security features from MCP 2025-06-18 specification
- Two client implementations:
  - Static client with pre-configured credentials
  - Auto-discovery client with dynamic registration

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

4. **Dynamic Client Registration (DCR)**
   - Allows clients to automatically register with new MCP servers
   - Eliminates the need for manual client registration processes
   - Enables seamless discovery and connection to new services
   - MCP specification strongly recommends implementing DCR since "clients do not know the set of MCP servers in advance"
   - Provides a standardized way to obtain OAuth client credentials
   - Follows RFC7591 (OAuth 2.0 Dynamic Client Registration Protocol)

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

## Quick Start

### Prerequisites
- Node.js installed
- AWS test account with access to:
    - Cognito for Authorization Server (1 user pool, 2 app clients)
    - API Gateway / Lambda / DynamoDB for DCR (2 resources, 2 functions, 1 table) 
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
   - `src/mcp-server/.env`
   - Compare with `.env.example` files
   - Manually verify/update CLIENT_SECRET if needed

### Running the Application
1. Start both clients and server
   ```bash
   npm run dev
   ```
2. Visit http://localhost:3000 to test the OAuth flow

3. Sign Up for a New User
   - Click the "Log in" button
   - Select "Sign up" in the Cognito hosted UI
   - Create a new user account
   - Verify your account by entering the confirmation code sent to your email
   - After successful verification, you'll be redirected back to the application

4. Click the "Fetch MCP Data" button to make an authenticated request to the MCP server

5. Visit http://localhost:3002 to test the DCR flow, auto-discovery client with Dynamic Client Registration.

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

- [Model Context Protocol Official Specification](https://modelcontextprotocol.io/specification/draft/basic/authorization)
- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12)
- [OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/rfc9728/)
- [OAuth 2.0 Dynamic Client Registration Protocol](https://datatracker.ietf.org/doc/rfc7591/)
- [AWS Cognito Developer Guide](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools.html)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Authors

- **Empires Security Labs** 🚀

