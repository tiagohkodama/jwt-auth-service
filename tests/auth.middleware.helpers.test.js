const { extractBearerToken } = require('../src/middleware/auth');

describe('Auth Middleware Helper Functions', () => {
  describe('extractBearerToken', () => {
    test('should extract token from valid Authorization header', () => {
      const req = {
        headers: {
          authorization: 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token'
        }
      };

      const token = extractBearerToken(req);
      expect(token).toBe('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token');
    });

    test('should extract token from case-insensitive Authorization header', () => {
      const req = {
        headers: {
          Authorization: 'Bearer test.jwt.token'
        }
      };

      const token = extractBearerToken(req);
      expect(token).toBe('test.jwt.token');
    });

    test('should return null for missing Authorization header', () => {
      const req = { headers: {} };
      
      const token = extractBearerToken(req);
      expect(token).toBeNull();
    });

    test('should return null for non-Bearer authorization', () => {
      const req = {
        headers: {
          authorization: 'Basic dXNlcjpwYXNz'
        }
      };

      const token = extractBearerToken(req);
      expect(token).toBeNull();
    });

    test('should return null for malformed Bearer header', () => {
      const req = {
        headers: {
          authorization: 'Bearer'
        }
      };

      const token = extractBearerToken(req);
      expect(token).toBeNull();
    });

    test('should return null for empty Bearer token', () => {
      const req = {
        headers: {
          authorization: 'Bearer '
        }
      };

      const token = extractBearerToken(req);
      expect(token).toBeNull();
    });

    test('should handle authorization header with extra spaces', () => {
      const req = {
        headers: {
          authorization: '  Bearer   test.token.here  '
        }
      };

      const token = extractBearerToken(req);
      expect(token).toBe('test.token.here');
    });

    test('should handle null authorization header', () => {
      const req = {
        headers: {
          authorization: null
        }
      };

      const token = extractBearerToken(req);
      expect(token).toBeNull();
    });

    test('should handle undefined authorization header', () => {
      const req = {
        headers: {
          authorization: undefined
        }
      };

      const token = extractBearerToken(req);
      expect(token).toBeNull();
    });

    test('should handle non-string authorization header', () => {
      const req = {
        headers: {
          authorization: 123
        }
      };

      const token = extractBearerToken(req);
      expect(token).toBeNull();
    });

    test('should handle authorization header with multiple spaces', () => {
      const req = {
        headers: {
          authorization: 'Bearer token1 token2 token3'
        }
      };

      const token = extractBearerToken(req);
      expect(token).toBe('token1');
    });
  });
});