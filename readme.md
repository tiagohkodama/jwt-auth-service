# JWT Auth Service

## Introduction
This service provides a lightweight authentication flow using JWT (RS256) to protect API endpoints.  
It offers:
- A login endpoint that issues signed JWT access tokens.
- A protected endpoint (`/me`) that returns user claims only when a valid token is supplied.
- A public JWKS endpoint for key verification.

## Tools and Technologies
- Node.js
- Express.js
- `jose` for JWT signing and verification (RS256)
- Jest + Supertest for testing

## How to Run

### 1. Install dependencies
```bash
npm install

2. Run tests

npm test

3. Start the application

npm start

4. Environment Variables (optional)

Create a .env file if you need custom values:

PORT=3000
ISSUER=auth-service
AUDIENCE=api
LOGIN_USERNAME=admin
LOGIN_PASSWORD=secret
TOKEN_TTL_SECONDS=3600

The service will run on:

http://localhost:3000

cURL Examples

Login to get a JWT

curl -s -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret"}'

Sample response:

{
  "access_token": "<JWT_TOKEN>",
  "token_type": "Bearer",
  "expires_in": 3600
}

Call protected /me endpoint

TOKEN=$(curl -s -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret"}' | jq -r .access_token)

curl -s http://localhost:3000/me \
  -H "Authorization: Bearer $TOKEN"

Fetch JWKS (public signing keys)

curl -s http://localhost:3000/.well-known/jwks.json