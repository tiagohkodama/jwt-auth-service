const request = require('supertest');
const { createKeys } = require('../src/lib/keys');
const buildServer = require('../src/server');

// Mock config module for consistent testing
jest.mock('../src/config', () => ({
  config: {
    port: 3000,
    jwt: {
      issuer: 'auth-service',
      audience: 'api',
      ttlSeconds: 3600
    },
    auth: {
      username: 'admin',
      password: 'secret'
    },
    nodeEnv: 'test',
    logLevel: 'error'
  },
  validateConfig: jest.fn()
}));

describe('JWT Auth Service - Integration Tests', () => {
  let app;
  let keys;

  beforeAll(async () => {
    keys = await createKeys();
    app = buildServer({ keys });
  });

  describe('Health Check Endpoint', () => {
    test('should return health status', async () => {
      const res = await request(app).get('/health');
      
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('status', 'healthy');
      expect(res.body).toHaveProperty('timestamp');
      expect(res.body).toHaveProperty('version');
      expect(new Date(res.body.timestamp)).toBeInstanceOf(Date);
    });

    test('should return consistent health check format', async () => {
      const res = await request(app).get('/health');
      
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(Object.keys(res.body)).toEqual(['status', 'timestamp', 'version']);
    });
  });

  describe('JWKS Endpoint', () => {
    test('should expose public keys at /.well-known/jwks.json', async () => {
      const res = await request(app).get('/.well-known/jwks.json');
      
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('keys');
      expect(Array.isArray(res.body.keys)).toBe(true);
      expect(res.body.keys).toHaveLength(1);
      expect(res.body.keys[0]).toHaveProperty('kid');
      expect(res.body.keys[0]).toHaveProperty('n'); // RSA modulus
      expect(res.body.keys[0]).toHaveProperty('e'); // RSA exponent
      expect(res.body.keys[0].alg).toBe('RS256');
      expect(res.body.keys[0].use).toBe('sig');
    });

    test('should return proper content type for JWKS', async () => {
      const res = await request(app).get('/.well-known/jwks.json');
      
      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    test('should have cacheable JWKS response', async () => {
      const res = await request(app).get('/.well-known/jwks.json');
      
      // JWKS should be cacheable (no cache-control: no-cache)
      expect(res.headers['cache-control']).not.toBe('no-cache');
    });
  });

  describe('Login Endpoint', () => {
    test('should return JWT token with valid credentials', async () => {
      const res = await request(app)
        .post('/login')
        .send({ username: 'admin', password: 'secret' })
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('access_token');
      expect(res.body).toHaveProperty('token_type', 'Bearer');
      expect(res.body).toHaveProperty('expires_in', 3600);
      expect(typeof res.body.access_token).toBe('string');
      expect(res.body.access_token.split('.')).toHaveLength(3); // JWT format
    });

    test('should return proper OAuth2-like response format', async () => {
      const res = await request(app)
        .post('/login')
        .send({ username: 'admin', password: 'secret' })
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(200);
      expect(Object.keys(res.body).sort()).toEqual(['access_token', 'expires_in', 'token_type']);
    });

    test('should reject invalid username', async () => {
      const res = await request(app)
        .post('/login')
        .send({ username: 'wrong', password: 'secret' })
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error', 'invalid_credentials');
      expect(res.body).toHaveProperty('message');
    });

    test('should reject invalid password', async () => {
      const res = await request(app)
        .post('/login')
        .send({ username: 'admin', password: 'wrong' })
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error', 'invalid_credentials');
      expect(res.body).toHaveProperty('message');
    });

    test('should reject missing credentials', async () => {
      const res = await request(app)
        .post('/login')
        .send({})
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'invalid_request');
      expect(res.body).toHaveProperty('message');
    });

    test('should handle missing username', async () => {
      const res = await request(app)
        .post('/login')
        .send({ password: 'secret' })
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'invalid_request');
    });

    test('should handle missing password', async () => {
      const res = await request(app)
        .post('/login')
        .send({ username: 'admin' })
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'invalid_request');
    });

    test('should handle null credentials', async () => {
      const res = await request(app)
        .post('/login')
        .send({ username: null, password: null })
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'invalid_request');
    });

    test('should handle empty string credentials', async () => {
      const res = await request(app)
        .post('/login')
        .send({ username: '', password: '' })
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'invalid_request');
    });

    test('should handle case-sensitive credentials', async () => {
      const res = await request(app)
        .post('/login')
        .send({ username: 'ADMIN', password: 'SECRET' })
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error', 'invalid_credentials');
    });

    test('should handle extra whitespace in credentials', async () => {
      const res = await request(app)
        .post('/login')
        .send({ username: ' admin ', password: ' secret ' })
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error', 'invalid_credentials');
    });

    test('should return different tokens for multiple requests', async () => {
      const res1 = await request(app)
        .post('/login')
        .send({ username: 'admin', password: 'secret' })
        .set('Content-Type', 'application/json');

      const res2 = await request(app)
        .post('/login')
        .send({ username: 'admin', password: 'secret' })
        .set('Content-Type', 'application/json');

      expect(res1.status).toBe(200);
      expect(res2.status).toBe(200);
      expect(res1.body.access_token).not.toBe(res2.body.access_token);
    });
  });

  describe('Protected /me Endpoint', () => {
    let validToken;

    beforeEach(async () => {
      const loginRes = await request(app)
        .post('/login')
        .send({ username: 'admin', password: 'secret' })
        .set('Content-Type', 'application/json');
      
      validToken = loginRes.body.access_token;
    });

    test('should return user claims with valid token', async () => {
      const res = await request(app)
        .get('/me')
        .set('Authorization', `Bearer ${validToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('sub', '1');
      expect(res.body).toHaveProperty('name', 'Admin');
      expect(res.body).toHaveProperty('role', 'admin');
      expect(res.body).toHaveProperty('iss', 'auth-service');
      expect(res.body).toHaveProperty('aud', 'api');
      expect(res.body).toHaveProperty('iat');
      expect(res.body).toHaveProperty('exp');
    });

    test('should return consistent user profile structure', async () => {
      const res = await request(app)
        .get('/me')
        .set('Authorization', `Bearer ${validToken}`);

      expect(res.status).toBe(200);
      const expectedKeys = ['sub', 'name', 'role', 'iss', 'aud', 'iat', 'exp'];
      expect(Object.keys(res.body).sort()).toEqual(expectedKeys.sort());
    });

    test('should validate token expiration time', async () => {
      const res = await request(app)
        .get('/me')
        .set('Authorization', `Bearer ${validToken}`);

      expect(res.status).toBe(200);
      expect(res.body.exp).toBeGreaterThan(res.body.iat);
      expect(res.body.exp - res.body.iat).toBe(3600); // TTL
    });

    test('should reject request without Authorization header', async () => {
      const res = await request(app).get('/me');
      
      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error', 'missing_token');
      expect(res.body).toHaveProperty('message');
    });

    test('should reject request with malformed Authorization header', async () => {
      const res = await request(app)
        .get('/me')
        .set('Authorization', 'InvalidFormat');
      
      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error', 'missing_token');
    });

    test('should reject request with invalid token', async () => {
      const res = await request(app)
        .get('/me')
        .set('Authorization', 'Bearer invalid.jwt.token');
      
      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error', 'invalid_token');
      expect(res.body).toHaveProperty('message');
    });

    test('should reject request with empty Bearer token', async () => {
      const res = await request(app)
        .get('/me')
        .set('Authorization', 'Bearer ');
      
      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error', 'missing_token');
    });

    test('should reject request with Basic auth', async () => {
      const res = await request(app)
        .get('/me')
        .set('Authorization', 'Basic YWRtaW46c2VjcmV0');
      
      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error', 'missing_token');
    });

    test('should handle case-insensitive Authorization header', async () => {
      const res = await request(app)
        .get('/me')
        .set('authorization', `Bearer ${validToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('sub', '1');
    });

    test('should work with uppercase Authorization header', async () => {
      const res = await request(app)
        .get('/me')
        .set('Authorization', `Bearer ${validToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('sub', '1');
    });
  });

  describe('404 Handler', () => {
    test('should return 404 for unknown GET endpoints', async () => {
      const res = await request(app).get('/unknown');
      
      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'not_found');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('GET');
      expect(res.body.message).toContain('/unknown');
    });

    test('should return 404 for unknown POST endpoints', async () => {
      const res = await request(app).post('/unknown');
      
      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'not_found');
      expect(res.body.message).toContain('POST');
    });

    test('should return 404 for unknown PUT endpoints', async () => {
      const res = await request(app).put('/unknown');
      
      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'not_found');
    });

    test('should return 404 for unknown DELETE endpoints', async () => {
      const res = await request(app).delete('/unknown');
      
      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'not_found');
    });

    test('should return 404 for unknown PATCH endpoints', async () => {
      const res = await request(app).patch('/unknown');
      
      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'not_found');
    });
  });

  describe('Error Handling', () => {
    test('should handle malformed JSON in login', async () => {
      const res = await request(app)
        .post('/login')
        .send('invalid json')
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(400);
    });

    test('should handle missing Content-Type header', async () => {
      const res = await request(app)
        .post('/login')
        .send('{"username":"admin","password":"secret"}');

      // Should still work as Express tries to parse
      expect([200, 400]).toContain(res.status);
    });

    test('should handle empty request body', async () => {
      const res = await request(app)
        .post('/login')
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'invalid_request');
    });
  });

  describe('Security Headers', () => {
    test('should not expose X-Powered-By header', async () => {
      const res = await request(app).get('/health');
      
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    test('should include security headers from Helmet', async () => {
      const res = await request(app).get('/health');
      
      // Helmet adds various security headers
      expect(res.headers['x-content-type-options']).toBeDefined();
      expect(res.headers['x-frame-options']).toBeDefined();
    });
  });

  describe('Content Type Handling', () => {
    test('should handle application/json content type', async () => {
      const res = await request(app)
        .post('/login')
        .send({ username: 'admin', password: 'secret' })
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(200);
    });

    test('should handle application/x-www-form-urlencoded content type', async () => {
      const res = await request(app)
        .post('/login')
        .send('username=admin&password=secret')
        .set('Content-Type', 'application/x-www-form-urlencoded');

      expect(res.status).toBe(200);
    });
  });

  describe('JWT Token Validation', () => {
    test('should create valid JWT structure', async () => {
      const res = await request(app)
        .post('/login')
        .send({ username: 'admin', password: 'secret' })
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(200);
      
      const token = res.body.access_token;
      const parts = token.split('.');
      
      expect(parts).toHaveLength(3);
      
      // Decode header
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      expect(header.alg).toBe('RS256');
      expect(header.typ).toBe('JWT');
      expect(header.kid).toBeDefined();
      
      // Decode payload
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      expect(payload.sub).toBe('1');
      expect(payload.name).toBe('Admin');
      expect(payload.role).toBe('admin');
      expect(payload.iss).toBe('auth-service');
      expect(payload.aud).toBe('api');
    });
  });
});