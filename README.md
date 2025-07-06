# Teleport‑to‑OIDC Bridge

A FastAPI-based OAuth 2.0 / OIDC provider that **authenticates users via Gravitational Teleport** and issues JWT tokens with user roles and policies for downstream applications. This project allows seamless Single Sign-On (SSO): once a user logs in to Teleport, they can access protected applications behind the bridge _without re-entering credentials_.  
Roles and policies are directly derived from Teleport, making the bridge ideal for integrating with MinIO or any OIDC-compatible service.

---

## Features

- **Acts as a stateless OIDC Provider** (authorization code flow)
- **No password prompt:** Users already logged into Teleport are automatically authenticated
- **JWT tokens signed with your own private key**
- **User roles and policies extracted from Teleport JWT**
- **OIDC Discovery and JWKS endpoints**
- **Minimal, self-contained** (no database; uses in-memory caches)
- **Debug logging** for easy troubleshooting

---

## Architecture Overview
```bash
+------------------+        +------------------+         +----------+
| Browser          |<------>| This OIDC Bridge |<------->| Teleport |
+------------------+        +------------------+         +----------+
|                                        ^
v                                        |
+------------------------------------------+
|         Your Application                 |
+------------------------------------------+
```
- Users authenticate to Teleport.
- Your app redirects to the OIDC Bridge for login (OAuth2 Authorization Code flow).
- The bridge validates the Teleport JWT and issues OIDC tokens with policies/roles.
- Your app consumes the OIDC tokens for authentication and authorization.

---

## Quickstart

### 1. Run with Docker

```bash
# Run the bridge (adjust env vars as needed)
docker run -p 8080:80 \
  -e BRIDGE_ISSUER="http://oidc-bridge.internal" \
  -e TELEPORT_JWKS_URL="https://teleport.example.com/v1/webapi/oidc/jwks" \
  -e TELEPORT_ISSUER="https://teleport.example.com:443" \
  -e TELEPORT_AUD="http://oidc-bridge.internal" \
  -v $(pwd)/idp-private.pem:/srv/idp-private.pem \
  abvabv/teleport-oidc-bridge:1.0.1
```

### 2 Teleport Configuration: Add Authorization Header

In your **Teleport configuration**, make sure to add the `Authorization` header to requests forwarded to the OIDC bridge:

```yaml
rewrite:
  headers:
    - "Authorization: Bearer {{internal.jwt}}"
```

This ensures that Teleport includes a valid JWT token when communicating with the OIDC bridge.

---

## Documentation

### Environment Variables

```
## Environment Variables

| Variable                  | Description                                                | Example Value                                        | Required |
|---------------------------|------------------------------------------------------------|------------------------------------------------------|----------|
| `BRIDGE_ISSUER`           | OIDC Issuer URL for this bridge.                           | `https://oidc-bridge.internal`                       | Yes      |
| `BRIDGE_JWKS_URI`         | (Usually auto-derived) JWKS endpoint for this bridge.      | `https://oidc-bridge.internal/.well-known/jwks.json` | No       |
| `BRIDGE_AUTH_ENDPOINT`    | (Usually auto-derived) Authorization endpoint.             | `https://oidc-bridge.internal/authorize`             | No       |
| `BRIDGE_TOKEN_ENDPOINT`   | (Usually auto-derived) Token endpoint.                     | `https://oidc-bridge.internal/token`                 | No       |
| `BRIDGE_USERINFO_ENDPOINT`| (Usually auto-derived) Userinfo endpoint.                  | `https://oidc-bridge.internal/userinfo`              | No       |
| `BRIDGE_KID`              | Key ID for JWT headers.                                    | `idpbridge`                                          | No       |
| `TELEPORT_JWKS_URL`       | JWKS endpoint for your Teleport cluster.                   | `https://tp.example.com/v1/webapi/oidc/jwks`         | Yes      |
| `TELEPORT_ISSUER`         | Issuer as set by Teleport OIDC.                            | `https://tp.example.com:443`                         | Yes      |
| `TELEPORT_AUD`            | Audience your app expects from Teleport.                   | `minio-app`                                          | Yes      |
| `PRIVATE_KEY_FILE`        | Path to PEM-encoded private key (used for JWT signing).    | `idp-private.pem`                                    | Yes      |
| `BRIDGE_PORT`             | Port for the app to listen on.                             | `80`                                                 | No       |
| `BRIDGE_DEBUG`            | Set to `true` for verbose debug logging.                   | `true` or `false`                                    | No       |

```

### Authorization Code Flow
1. Authorize Endpoint
Client app redirects user to /authorize, providing:
client_id, redirect_uri, state, etc.
User’s Teleport JWT in Authorization: Bearer ... header

2. Token Endpoint
After successful Teleport JWT validation, user is redirected back with code.
Client exchanges code for tokens via /token.

3. Userinfo Endpoint
Applications can retrieve user claims (including policy) via /userinfo.

### API Endpoints
1. OIDC Discovery
GET /.well-known/openid-configuration
Returns OIDC provider metadata.

2. JWKS
GET /.well-known/jwks.json
Returns public key for JWT verification.

3. Authorization
GET /authorize
Standard OIDC authorize endpoint. Requires valid Teleport JWT in Authorization header.

4. Token
POST /token
Exchange authorization code for tokens.

5. Userinfo
GET/POST /userinfo
Returns user claims extracted from the JWT.

### Teleport Roles → Policy Extraction
Roles and traits are extracted directly from Teleport’s JWT.

Policy claim is derived by:

Matching Teleport roles to the client_id (see code for details)

If traits.policy is present, it is used directly.

### Security Notes
Tokens are short-lived (1 hour) and stored in-memory only during exchange.

Private key should be stored securely and never committed to version control.

Enable BRIDGE_DEBUG=true only for troubleshooting—debug logs may include sensitive info!

### How to Generate idp-private.pem for the OIDC Bridge
```bash
# Generate private key
openssl genrsa -out idp-private.pem 2048

# (Optional) Check key details
openssl rsa -in idp-private.pem -check
```
### Examples
Examples of configuration for different services using OIDC Bridge for authentication can be found in the `examples` directory.

### Contributing
Contributions and suggestions welcome! Please file issues or PRs for improvements.

License
MIT


