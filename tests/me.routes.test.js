const request = require('supertest');
const express = require('express');
const createMeRoutes = require('../src/routes/me');

describe('Me Routes', () => {
  let app;
  let mockAuthMiddleware;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    
    // Mock auth middleware
    mockAuthMiddleware = jest.fn((req, res, next) => {
      // Simulate successful authentication
      req.user = {
        sub: '1',
        name: 'Test User',
        role: 'admin',
        iss: 'test-issuer',
        aud: 'test-audience',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600
      };
      next();
    });
  });

  describe('Route Creation', () => {
    test('should create routes with valid dependencies', () => {
      expect(() => {
        createMeRoutes({ app, authMiddleware: mockAuthMiddleware });
      }).not.toThrow();
    });

    test('should throw error when app is missing', () => {
      expect(() => {
        createMeRoutes({ authMiddleware: mockAuthMiddleware });
      }).toThrow('App and authMiddleware are required dependencies');
    });

    test('should throw error when authMiddleware is missing', () => {
      expect(() => {
        createMeRoutes({ app });
      }).toThrow('App and authMiddleware are required dependencies');
    });

    test('should throw error when both dependencies are missing', () => {
      expect(() => {
        createMeRoutes({});
      }).toThrow('App and authMiddleware are required dependencies');
    });
  });

  describe('GET /me endpoint', () => {
    beforeEach(() => {
      createMeRoutes({ app, authMiddleware: mockAuthMiddleware });
    });

    test('should return user profile with valid authentication', async () => {
      const res = await request(app).get('/me');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        sub: '1',
        name: 'Test User',
        role: 'admin',
        iss: 'test-issuer',
        aud: 'test-audience',
        iat: expect.any(Number),
        exp: expect.any(Number)
      });
    });

    test('should call auth middleware before handler', async () => {
      await request(app).get('/me');

      expect(mockAuthMiddleware).toHaveBeenCalledTimes(1);
    });

    test('should handle missing user object gracefully', async () => {
      // Mock middleware that doesn't set req.user
      const noUserMiddleware = jest.fn((req, res, next) => {
        next();
      });

      const testApp = express();
      testApp.use(express.json());
      createMeRoutes({ app: testApp, authMiddleware: noUserMiddleware });

      const res = await request(testApp).get('/me');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        sub: undefined,
        name: undefined,
        role: undefined,
        iss: undefined,
        aud: undefined,
        iat: undefined,
        exp: undefined
      });
    });

    test('should handle partial user object', async () => {
      const partialUserMiddleware = jest.fn((req, res, next) => {
        req.user = {
          sub: '2',
          name: 'Partial User'
          // Missing other fields
        };
        next();
      });

      const testApp = express();
      testApp.use(express.json());
      createMeRoutes({ app: testApp, authMiddleware: partialUserMiddleware });

      const res = await request(testApp).get('/me');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        sub: '2',
        name: 'Partial User',
        role: undefined,
        iss: undefined,
        aud: undefined,
        iat: undefined,
        exp: undefined
      });
    });

    test('should handle null user object', async () => {
      const nullUserMiddleware = jest.fn((req, res, next) => {
        req.user = null;
        next();
      });

      const testApp = express();
      testApp.use(express.json());
      createMeRoutes({ app: testApp, authMiddleware: nullUserMiddleware });

      const res = await request(testApp).get('/me');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        sub: undefined,
        name: undefined,
        role: undefined,
        iss: undefined,
        aud: undefined,
        iat: undefined,
        exp: undefined
      });
    });

    test('should only return expected user profile fields', async () => {
      // Mock middleware with extra fields
      const extraFieldsMiddleware = jest.fn((req, res, next) => {
        req.user = {
          sub: '1',
          name: 'Test User',
          role: 'admin',
          iss: 'test-issuer',
          aud: 'test-audience',
          iat: 1234567890,
          exp: 1234571490,
          // Extra fields that should not be returned
          password: 'secret',
          internalId: 'internal-123',
          permissions: ['read', 'write']
        };
        next();
      });

      const testApp = express();
      testApp.use(express.json());
      createMeRoutes({ app: testApp, authMiddleware: extraFieldsMiddleware });

      const res = await request(testApp).get('/me');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        sub: '1',
        name: 'Test User',
        role: 'admin',
        iss: 'test-issuer',
        aud: 'test-audience',
        iat: 1234567890,
        exp: 1234571490
      });

      // Ensure extra fields are not included
      expect(res.body).not.toHaveProperty('password');
      expect(res.body).not.toHaveProperty('internalId');
      expect(res.body).not.toHaveProperty('permissions');
    });

    test('should handle different data types in user object', async () => {
      const mixedDataMiddleware = jest.fn((req, res, next) => {
        req.user = {
          sub: 123, // Number instead of string
          name: null,
          role: '',
          iss: 'test-issuer',
          aud: ['api1', 'api2'], // Array instead of string
          iat: '1234567890', // String instead of number
          exp: 1234571490
        };
        next();
      });

      const testApp = express();
      testApp.use(express.json());
      createMeRoutes({ app: testApp, authMiddleware: mixedDataMiddleware });

      const res = await request(testApp).get('/me');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        sub: 123,
        name: null,
        role: '',
        iss: 'test-issuer',
        aud: ['api1', 'api2'],
        iat: '1234567890',
        exp: 1234571490
      });
    });
  });

  describe('Error Handling', () => {
    test('should handle middleware errors gracefully', async () => {
      const errorMiddleware = jest.fn((req, res, next) => {
        throw new Error('Middleware error');
      });

      const testApp = express();
      testApp.use(express.json());
      createMeRoutes({ app: testApp, authMiddleware: errorMiddleware });

      // Add error handler
      testApp.use((error, req, res, next) => {
        res.status(500).json({ error: 'Internal server error' });
      });

      const res = await request(testApp).get('/me');

      expect(res.status).toBe(500);
    });

    test('should handle async middleware errors', async () => {
      const asyncErrorMiddleware = jest.fn(async (req, res, next) => {
        return next(new Error('Async middleware error'));
      });

      const testApp = express();
      testApp.use(express.json());
      createMeRoutes({ app: testApp, authMiddleware: asyncErrorMiddleware });

      // Error handler
      testApp.use((error, req, res, next) => {
        res.status(500).json({ error: 'Internal server error' });
      });

      const res = await request(testApp).get('/me');
      expect(res.status).toBe(500);
    });
  });

  describe('HTTP Methods', () => {
    beforeEach(() => {
      createMeRoutes({ app, authMiddleware: mockAuthMiddleware });
    });

    test('should only respond to GET requests', async () => {
      const getRes = await request(app).get('/me');
      expect(getRes.status).toBe(200);

      const postRes = await request(app).post('/me');
      expect(postRes.status).toBe(404);

      const putRes = await request(app).put('/me');
      expect(putRes.status).toBe(404);

      const deleteRes = await request(app).delete('/me');
      expect(deleteRes.status).toBe(404);
    });
  });

  describe('Response Format', () => {
    beforeEach(() => {
      createMeRoutes({ app, authMiddleware: mockAuthMiddleware });
    });

    test('should return JSON content type', async () => {
      const res = await request(app).get('/me');

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/application\/json/);
    });

    test('should return consistent field order', async () => {
      const res = await request(app).get('/me');

      expect(res.status).toBe(200);
      const expectedFields = ['sub', 'name', 'role', 'iss', 'aud', 'iat', 'exp'];
      expect(Object.keys(res.body)).toEqual(expectedFields);
    });
  });
});