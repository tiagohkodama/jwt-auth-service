const request = require('supertest');
const buildServer = require('../src/server');
const { createKeys } = require('../src/lib/keys');

// Mock config module
jest.mock('../src/config', () => ({
  config: {
    nodeEnv: 'test',
    jwt: {
      issuer: 'test-issuer',
      audience: 'test-audience',
      ttlSeconds: 3600
    },
    auth: {
      username: 'admin',
      password: 'secret'
    }
  }
}));

describe('Server Building and Error Handling', () => {
  let keys;
  let app;

  beforeAll(async () => {
    keys = await createKeys();
    app = buildServer({ keys });
  });

  describe('Server Building', () => {
    test('should build server with valid keys', () => {
      const testApp = buildServer({ keys });
      expect(testApp).toBeDefined();
      expect(typeof testApp.listen).toBe('function');
    });

    test('should throw error when keys are missing', () => {
      expect(() => buildServer({})).toThrow('Keys are required to build server');
      expect(() => buildServer()).toThrow('Keys are required to build server');
    });

    test('should configure Express app properly', () => {
      const testApp = buildServer({ keys });
      
      // Test that Express app has expected properties
      expect(testApp.get).toBeDefined();
      expect(testApp.post).toBeDefined();
      expect(testApp.use).toBeDefined();
      expect(testApp.listen).toBeDefined();
    });
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
  });

  describe('JWKS Endpoint', () => {
    test('should return JWKS successfully', async () => {
      const res = await request(app).get('/.well-known/jwks.json');
      
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('keys');
      expect(Array.isArray(res.body.keys)).toBe(true);
    });

    test('should handle JWKS endpoint errors gracefully', async () => {
      // Create app with corrupted keys to trigger error
      const corruptedKeys = { ...keys, jwks: null };
      const testApp = buildServer({ keys: corruptedKeys });
      
      const res = await request(testApp).get('/.well-known/jwks.json');
      
      expect(res.status).toBe(500);
      expect(res.body).toHaveProperty('error', 'internal_server_error');
      expect(res.body).toHaveProperty('message');
    });
  });

  describe('404 Handler', () => {
    test('should return 404 for GET requests to unknown endpoints', async () => {
      const res = await request(app).get('/unknown-endpoint');
      
      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'not_found');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('GET');
      expect(res.body.message).toContain('/unknown-endpoint');
    });

    test('should return 404 for POST requests to unknown endpoints', async () => {
      const res = await request(app).post('/unknown-endpoint');
      
      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'not_found');
      expect(res.body).toHaveProperty('message');
      expect(res.body.message).toContain('POST');
      expect(res.body.message).toContain('/unknown-endpoint');
    });

    test('should return 404 for PUT requests to unknown endpoints', async () => {
      const res = await request(app).put('/unknown-endpoint');
      
      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'not_found');
    });

    test('should return 404 for DELETE requests to unknown endpoints', async () => {
      const res = await request(app).delete('/unknown-endpoint');
      
      expect(res.status).toBe(404);
      expect(res.body).toHaveProperty('error', 'not_found');
    });
  });

  describe('Global Error Handler', () => {
    test('should handle JSON parsing errors', async () => {
      const res = await request(app)
        .post('/login')
        .send('invalid json')
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(400);
    });

    test('should handle large request bodies', async () => {
      const largePayload = 'x'.repeat(11 * 1024 * 1024); // 11MB payload
      
      const res = await request(app)
        .post('/login')
        .send(largePayload)
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(413); // Payload too large
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

  describe('Request Parsing', () => {
    test('should parse JSON request bodies', async () => {
      const res = await request(app)
        .post('/login')
        .send({ username: 'admin', password: 'secret' })
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(200);
    });

    test('should parse URL-encoded request bodies', async () => {
      const res = await request(app)
        .post('/login')
        .send('username=admin&password=secret')
        .set('Content-Type', 'application/x-www-form-urlencoded');

      expect(res.status).toBe(200);
    });
  });
});