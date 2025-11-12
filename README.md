# JWT Auth Service

A production-ready, lightweight JWT authentication service built with Node.js, Express, and RS256 JWT tokens. This service demonstrates clean architecture principles, comprehensive testing, and security best practices.

## Features

- **JWT Authentication**: RS256 signed JWT tokens with configurable expiration
- **Protected Routes**: Middleware-based route protection
- **JWKS Endpoint**: Public key discovery for token verification
- **Security First**: Helmet.js security headers, input validation, error handling
- **Clean Architecture**: SOLID principles, dependency injection, separation of concerns
- **Comprehensive Testing**: Unit tests, integration tests, and manual test scripts
- **Production Ready**: Graceful shutdown, health checks, logging, configuration management

## Architecture

The service follows clean architecture principles with clear separation of concerns:

```
src/
├── config/          # Configuration management
├── lib/             # Core business logic (key generation)
├── middleware/      # Express middleware (authentication)
├── routes/          # HTTP route handlers (controllers)
├── server.js        # Express server setup
└── index.js         # Application entry point

tests/               # Comprehensive test suite
scripts/             # Development and testing scripts
```

## API Endpoints

| Method | Endpoint | Description | Authentication |
|--------|----------|-------------|----------------|
| `GET` | `/health` | Health check | None |
| `POST` | `/login` | Authenticate and get JWT token | None |
| `GET` | `/me` | Get user profile from JWT claims | Bearer Token |
| `GET` | `/.well-known/jwks.json` | Public keys for JWT verification | None |

## Quick Start

### Prerequisites

- Node.js >= 18.17
- npm or yarn

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd jwt-auth-service

# Install dependencies
npm install

# Run tests
npm test

# Start the service
npm start
```

The service will be available at `http://localhost:3000`

### Using Make (Optional)

```bash
make setup    # Install dependencies
make test     # Run tests
make dev      # Start development server
make api-test # Test API endpoints
```

## Configuration

Create a `.env` file (see `.env.example`):

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# JWT Configuration
ISSUER=auth-service
AUDIENCE=api
TOKEN_TTL_SECONDS=3600

# Authentication Configuration
LOGIN_USERNAME=admin
LOGIN_PASSWORD=secret

# Logging
LOG_LEVEL=info
```

## Usage Examples

### 1. Login and Get JWT Token

```bash
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret"}'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQ1Njc4LTkwYWItY2RlZi0xMjM0LTU2Nzg5MGFiY2RlZiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### 2. Access Protected Endpoint

```bash
# Extract token from login response
TOKEN=$(curl -s -X POST http://localhost:3000/login \
  -H "Content-Type": application/json" \
  -d '{"username":"admin","password":"secret"}' | jq -r .access_token)

# Use token to access protected endpoint
curl http://localhost:3000/me \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**
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

### 3. Get Public Keys (JWKS)

```bash
curl http://localhost:3000/.well-known/jwks.json
```

**Response:**
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

## Testing

### Run All Tests

```bash
npm test
```

### Run Tests with Coverage

```bash
npm run test:coverage
```

### Run Tests in Watch Mode

```bash
npm run test:watch
```

### Manual API Testing

```bash
# Start the server first
npm start

# In another terminal, run API tests
./scripts/quick-test.sh
# or
make api-test
```

## Security Features

- **RS256 JWT Tokens**: Asymmetric cryptography for token signing
- **Helmet.js**: Security headers (XSS protection, HSTS, etc.)
- **Input Validation**: Request body validation and sanitization
- **Error Handling**: No sensitive information leaked in error responses
- **CORS Ready**: Easy to configure for cross-origin requests
- **Rate Limiting Ready**: Structure supports rate limiting middleware

## Production Deployment

### Environment Variables

Ensure all required environment variables are set:

```bash
export NODE_ENV=production
export PORT=3000
export ISSUER=your-service-name
export AUDIENCE=your-api-audience
export LOGIN_USERNAME=your-username
export LOGIN_PASSWORD=your-secure-password
export TOKEN_TTL_SECONDS=3600
```

### Health Checks

The service provides a health check endpoint at `/health` for load balancers and monitoring systems.

### Graceful Shutdown

The service handles `SIGTERM` and `SIGINT` signals for graceful shutdown in containerized environments.

### Logging

Structured logging with different levels for development and production environments.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
