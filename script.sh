#!/usr/bin/env bash set -euo pipefail

Scaffold a minimal, production-ready JWT Auth Service (Express + jose + Jest)

Usage:

bash scaffold-jwt-auth-service.sh [project-dir]

Example:

bash scaffold-jwt-auth-service.sh jwt-auth-service

PROJECT_DIR=${1:-jwt-auth-service}

mkdir -p "$PROJECT_DIR" cd "$PROJECT_DIR"

--- package.json ---

cat > package.json <<'JSON' { "name": "jwt-auth-service", "version": "1.0.0", "private": true, "description": "Lightweight JWT auth service with RS256 (Express + jose)", "type": "commonjs", "engines": { "node": ">=18.17" }, "scripts": { "start": "node src/index.js", "dev": "nodemon --ext js --watch src --exec node src/index.js", "test": "jest --runInBand" }, "dependencies": { "dotenv": "^16.4.5", "express": "^4.21.1", "helmet": "^7.1.0", "jose": "^5.9.2", "morgan": "^1.10.0" }, "devDependencies": { "jest": "^29.7.0", "supertest": "^7.1.1", "nodemon": "^3.0.1" }, "jest": { "testEnvironment": "node", "collectCoverage": true, "collectCoverageFrom": [ "src/**/*.js", "!src/index.js" ] } } JSON

--- .gitignore ---

cat > .gitignore <<'GIT' node_modules coverage .env GIT

--- README.md ---

cat > README.md <<'MD'

JWT Auth Service

A lightweight authentication service that issues and validates RS256 JWTs.

Endpoints

POST /login — mock credentials to receive a JWT

GET /me — protected route, returns token claims

GET /.well-known/jwks.json — public JWKS for the current key set


Quick start

# 1) Install deps
npm install
# 2) Run tests
npm test
# 3) Start the service
npm start
# Service runs on http://localhost:3000

Environment

Optional .env:

PORT=3000
ISSUER=auth-service
AUDIENCE=api
LOGIN_USERNAME=admin
LOGIN_PASSWORD=secret
TOKEN_TTL_SECONDS=3600

Example requests (curl)

Login and get a JWT

curl -s -X POST http://localhost:3000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"secret"}' | jq

Response:

{ "access_token": "<JWT>", "token_type": "Bearer", "expires_in": 3600 }

Call protected /me

TOKEN="$(curl -s -X POST http://localhost:3000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"secret"}' | jq -r .access_token)"

curl -s http://localhost:3000/me -H "Authorization: Bearer $TOKEN" | jq

Fetch JWKS

curl -s http://localhost:3000/.well-known/jwks.json | jq

Testing

Jest tests cover the authentication flow end-to-end using Supertest.

npm test

MD

--- src structure ---

mkdir -p src/{config,lib,middleware,routes}

--- src/index.js ---

cat > src/index.js <<'JS' require('dotenv').config(); const { createKeys } = require('./lib/keys'); const buildServer = require('./server');

(async () => { const keys = await createKeys(); const app = buildServer({ keys }); const port = Number(process.env.PORT || 3000); app.listen(port, () => { // eslint-disable-next-line no-console console.log([auth] listening on http://localhost:${port}); }); })(); JS

--- src/lib/keys.js ---

cat > src/lib/keys.js <<'JS' const crypto = require('crypto'); const { generateKeyPair, exportJWK, createLocalJWKSet } = require('jose');

async function createKeys() { const { publicKey, privateKey } = await generateKeyPair('RS256', { modulusLength: 2048 }); const kid = crypto.randomUUID(); const publicJwk = await exportJWK(publicKey); publicJwk.kid = kid; publicJwk.alg = 'RS256'; const jwks = { keys: [publicJwk] }; const jwkSet = createLocalJWKSet(jwks); return { privateKey, kid, jwks, jwkSet }; }

module.exports = { createKeys }; JS

--- src/middleware/auth.js ---

cat > src/middleware/auth.js <<'JS' const { jwtVerify } = require('jose');

function bearer(req) { const h = req.headers['authorization'] || req.headers['Authorization']; if (!h) return null; const [type, token] = String(h).split(' '); if (type !== 'Bearer' || !token) return null; return token; }

function auth({ keys }) { const issuer = process.env.ISSUER || 'auth-service'; const audience = process.env.AUDIENCE || 'api';

return async (req, res, next) => { try { const token = bearer(req); if (!token) return res.status(401).json({ error: 'missing_token' }); const { payload } = await jwtVerify(token, keys.jwkSet, { algorithms: ['RS256'], issuer, audience }); req.user = payload; return next(); } catch (err) { return res.status(401).json({ error: 'invalid_token' }); } }; }

module.exports = auth; JS

--- src/routes/auth.js ---

cat > src/routes/auth.js <<'JS' const { SignJWT } = require('jose');

module.exports = function authRoutes({ app, keys }) { const issuer = process.env.ISSUER || 'auth-service'; const audience = process.env.AUDIENCE || 'api'; const ttl = Number(process.env.TOKEN_TTL_SECONDS || 3600);

app.post('/login', async (req, res) => { const { username, password } = req.body || {}; const expectedUser = process.env.LOGIN_USERNAME || 'admin'; const expectedPass = process.env.LOGIN_PASSWORD || 'secret';

// Mock credential check
if (username !== expectedUser || password !== expectedPass) {
  return res.status(401).json({ error: 'invalid_credentials' });
}

const now = Math.floor(Date.now() / 1000);
const claims = {
  sub: '1',
  name: 'Admin',
  role: 'admin'
};

const token = await new SignJWT(claims)
  .setProtectedHeader({ alg: 'RS256', kid: keys.kid })
  .setIssuer(issuer)
  .setAudience(audience)
  .setIssuedAt(now)
  .setExpirationTime(now + ttl)
  .sign(keys.privateKey);

return res.json({ access_token: token, token_type: 'Bearer', expires_in: ttl });

}); }; JS

--- src/routes/me.js ---

cat > src/routes/me.js <<'JS' module.exports = function meRoutes({ app, authMw }) { app.get('/me', authMw, (req, res) => { // Minimal profile derived from JWT claims const { sub, name, role, iss, aud, iat, exp } = req.user || {}; res.json({ sub, name, role, iss, aud, iat, exp }); }); }; JS

--- src/server.js ---

cat > src/server.js <<'JS' const express = require('express'); const helmet = require('helmet'); const morgan = require('morgan'); const auth = require('./middleware/auth');

function buildServer({ keys }) { const app = express(); app.disable('x-powered-by'); app.use(helmet()); app.use(express.json()); app.use(morgan('tiny'));

// JWKS endpoint (public) app.get('/.well-known/jwks.json', (req, res) => res.json(keys.jwks));

// Routes require('./routes/auth')({ app, keys }); const authMw = auth({ keys }); require('./routes/me')({ app, authMw });

// 404 fallback app.use((req, res) => res.status(404).json({ error: 'not_found' }));

return app; }

module.exports = buildServer; JS

--- tests/auth.test.js ---

mkdir -p tests cat > tests/auth.test.js <<'JS' const request = require('supertest'); const { createKeys } = require('../src/lib/keys'); const buildServer = require('../src/server');

describe('Auth flow', () => { let app;

beforeAll(async () => { process.env.ISSUER = 'auth-service'; process.env.AUDIENCE = 'api'; process.env.LOGIN_USERNAME = 'admin'; process.env.LOGIN_PASSWORD = 'secret'; const keys = await createKeys(); app = buildServer({ keys }); });

test('JWKS endpoint exposes a public key', async () => { const res = await request(app).get('/.well-known/jwks.json'); expect(res.status).toBe(200); expect(res.body).toHaveProperty('keys'); expect(Array.isArray(res.body.keys)).toBe(true); expect(res.body.keys[0]).toHaveProperty('kid'); expect(res.body.keys[0]).toHaveProperty('n'); // RSA modulus });

test('login succeeds with mock credentials and returns a bearer token', async () => { const res = await request(app) .post('/login') .send({ username: 'admin', password: 'secret' }) .set('Content-Type', 'application/json');

expect(res.status).toBe(200);
expect(res.body).toHaveProperty('access_token');
expect(res.body).toMatchObject({ token_type: 'Bearer' });

});

test('protected /me returns claims when a valid token is supplied', async () => { const login = await request(app) .post('/login') .send({ username: 'admin', password: 'secret' }) .set('Content-Type', 'application/json');

const token = login.body.access_token;

const me = await request(app)
  .get('/me')
  .set('Authorization', `Bearer ${token}`);

expect(me.status).toBe(200);
expect(me.body).toHaveProperty('sub', '1');
expect(me.body).toHaveProperty('name', 'Admin');

});

test('missing token yields 401', async () => { const res = await request(app).get('/me'); expect(res.status).toBe(401); expect(res.body).toHaveProperty('error', 'missing_token'); });

test('invalid token yields 401', async () => { const res = await request(app) .get('/me') .set('Authorization', 'Bearer not.a.jwt'); expect(res.status).toBe(401); expect(res.body).toHaveProperty('error', 'invalid_token'); }); }); JS

--- Done ---

echo "\nProject scaffolded at: $(pwd)"