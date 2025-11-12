# JWT Auth Service API Documentation

## Base URL

```
http://localhost:3000
```

## Authentication

This service uses JWT (JSON Web Tokens) with RS256 algorithm for authentication. Protected endpoints require a valid JWT token in the Authorization header.

### Authorization Header Format

```
Authorization: Bearer <jwt_token>
```

## Endpoints

### 1. Health Check

Check if the service is running and healthy.

**Endpoint:** `GET /health`

**Authentication:** None required

**Response:**

```json
{
  "status": "healthy",
  "timestamp": "2023-12-01T10:30:00.000Z",
  "version": "1.0.0"
}
```

**Status Codes:**
- `200 OK` - Service is healthy

---

### 2. User Authentication (Login)

Authenticate a user and receive a JWT access token.

**Endpoint:** `POST /login`

**Authentication:** None required

**Request Body:**

```json
{
  "username": "admin",
  "password": "secret"
}
```

**Request Headers:**
```
Content-Type: application/json
```

**Success Response:**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQ1Njc4LTkwYWItY2RlZi0xMjM0LTU2Nzg5MGFiY2RlZiJ9.eyJzdWIiOiIxIiwibmFtZSI6IkFkbWluIiwicm9sZSI6ImFkbWluIiwiaXNzIjoiYXV0aC1zZXJ2aWNlIiwiYXVkIjoiYXBpIiwiaWF0IjoxNzAzMTIzNDU2LCJleHAiOjE3MDMxMjcwNTZ9.signature",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Error Responses:**

**400 Bad Request** - Missing or invalid request body:
```json
{
  "error": "invalid_request",
  "message": "Username and password are required"
}
```

**401 Unauthorized** - Invalid credentials:
```json
{
  "error": "invalid_credentials",
  "message": "Invalid username or password"
}
```

**Status Codes:**
- `200 OK` - Authentication successful
- `400 Bad Request` - Invalid request format
- `401 Unauthorized` - Invalid credentials
- `500 Internal Server Error` - Server error

---

### 3. Get User Profile

Retrieve the current user's profile information from JWT claims.

**Endpoint:** `GET /me`

**Authentication:** Bearer token required

**Request Headers:**
```
Authorization: Bearer <jwt_token>
```

**Success Response:**

```json
{
  "sub": "1",
  "name": "Admin",
  "role": "admin",
  "iss": "auth-service",
  "aud": "api",
  "iat": 1703123456,
  "exp": 1703127056
}
```

**Response Fields:**
- `sub` - Subject (user ID)
- `name` - User's display name
- `role` - User's role
- `iss` - Token issuer
- `aud` - Token audience
- `iat` - Issued at (Unix timestamp)
- `exp` - Expires at (Unix timestamp)

**Error Responses:**

**401 Unauthorized** - Missing token:
```json
{
  "error": "missing_token",
  "message": "Authorization header with Bearer token is required"
}
```

**401 Unauthorized** - Invalid or expired token:
```json
{
  "error": "invalid_token",
  "message": "Invalid or expired token"
}
```

**Status Codes:**
- `200 OK` - Profile retrieved successfully
- `401 Unauthorized` - Missing, invalid, or expired token
- `500 Internal Server Error` - Server error

---

### 4. JSON Web Key Set (JWKS)

Retrieve the public keys used to verify JWT tokens.

**Endpoint:** `GET /.well-known/jwks.json`

**Authentication:** None required

**Success Response:**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "12345678-90ab-cdef-1234-567890abcdef",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB"
    }
  ]
}
```

**Response Fields:**
- `kty` - Key type (RSA)
- `use` - Key usage (sig for signature)
- `kid` - Key ID (unique identifier)
- `alg` - Algorithm (RS256)
- `n` - RSA modulus
- `e` - RSA exponent

**Status Codes:**
- `200 OK` - JWKS retrieved successfully
- `500 Internal Server Error` - Server error

---

## Error Handling

All endpoints follow a consistent error response format:

```json
{
  "error": "error_code",
  "message": "Human-readable error description"
}
```

### Common Error Codes

- `invalid_request` - Malformed request (missing required fields, invalid JSON)
- `invalid_credentials` - Authentication failed
- `missing_token` - Authorization header missing or malformed
- `invalid_token` - JWT token is invalid, expired, or malformed
- `not_found` - Requested resource not found
- `internal_server_error` - Unexpected server error

## Rate Limiting

Currently, no rate limiting is implemented, but the architecture supports adding rate limiting middleware.

## CORS

Cross-Origin Resource Sharing (CORS) is not configured by default. Add CORS middleware if needed for browser-based applications.

## Examples

### Complete Authentication Flow

```bash
# 1. Login to get token
TOKEN=$(curl -s -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret"}' | jq -r .access_token)

# 2. Use token to access protected resource
curl -s http://localhost:3000/me \
  -H "Authorization: Bearer $TOKEN" | jq .

# 3. Verify token using public keys
curl -s http://localhost:3000/.well-known/jwks.json | jq .
```

### Token Verification (External Services)

External services can verify JWT tokens using the JWKS endpoint:

1. Fetch public keys from `/.well-known/jwks.json`
2. Use the appropriate key (matching `kid`) to verify the token signature
3. Validate token claims (`iss`, `aud`, `exp`, etc.)

### JWT Token Structure

The JWT tokens contain the following claims:

```json
{
  "sub": "1",           // Subject (user ID)
  "name": "Admin",      // User name
  "role": "admin",      // User role
  "iss": "auth-service", // Issuer
  "aud": "api",         // Audience
  "iat": 1703123456,    // Issued at
  "exp": 1703127056     // Expires at
}
```

## Security Considerations

1. **Token Storage**: Store JWT tokens securely (httpOnly cookies recommended for web apps)
2. **Token Expiration**: Tokens expire after the configured TTL (default: 1 hour)
3. **HTTPS**: Always use HTTPS in production
4. **Key Rotation**: Implement key rotation for enhanced security
5. **Audience Validation**: Validate the `aud` claim matches your service
6. **Issuer Validation**: Validate the `iss` claim matches the expected issuer