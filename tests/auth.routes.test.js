const { validateCredentials, createJwtToken } = require('../src/routes/auth');
const { createKeys } = require('../src/lib/keys');

// Mock config module
jest.mock('../src/config', () => ({
  config: {
    auth: {
      username: 'testuser',
      password: 'testpass'
    },
    jwt: {
      issuer: 'test-issuer',
      audience: 'test-audience',
      ttlSeconds: 3600
    }
  }
}));

const { config } = require('../src/config')


describe('Auth Routes Helper Functions', () => {
  describe('validateCredentials', () => {
    const expected = { username: 'testuser', password: 'testpass' };

    test('should return true for valid credentials', () => {
      const creds = { username: 'testuser', password: 'testpass' };
      const result = validateCredentials(creds, expected);
      expect(result).toBe(true);
    });

    test('should return false for invalid username', () => {
      const creds = { username: 'wronguser', password: 'testpass' };
      const result = validateCredentials(creds, expected);
      expect(result).toBe(false);
    });

    test('should return false for invalid password', () => {
      const creds = { username: 'testuser', password: 'wrongpass' };
      const result = validateCredentials(creds, expected);
      expect(result).toBe(false);
    });

    test('should return false for both invalid credentials', () => {
      const creds = { username: 'wronguser', password: 'wrongpass' };
      const result = validateCredentials(creds, expected);
      expect(result).toBe(false);
    });

    test('should handle undefined credentials', () => {
      // creds param undefined (uses default {}), does not match expected
      expect(validateCredentials(undefined, expected)).toBe(false);

      // missing password
      expect(validateCredentials({ username: 'testuser' }, expected)).toBe(false);

      // missing username
      expect(validateCredentials({ password: 'testpass' }, expected)).toBe(false);
    });

    test('should handle null credentials', () => {
      // creds is null (optional chaining handles it), does not match expected
      expect(validateCredentials(null, expected)).toBe(false);

      // non-string properties are treated as empty strings
      expect(validateCredentials({ username: null, password: 'testpass' }, expected)).toBe(false);
      expect(validateCredentials({ username: 'testuser', password: null }, expected)).toBe(false);
    });

    test('should handle empty string credentials', () => {
      expect(validateCredentials({ username: '', password: 'testpass' }, expected)).toBe(false);
      expect(validateCredentials({ username: 'testuser', password: '' }, expected)).toBe(false);
      expect(validateCredentials({ username: '', password: '' }, expected)).toBe(false);
    });

    test('should throw if expected is missing or invalid', () => {
      const creds = { username: 'testuser', password: 'testpass' };
      expect(() => validateCredentials(creds)).toThrow();
      expect(() => validateCredentials(creds, null)).toThrow();
    });
  });

  describe('createJwtToken', () => {
    let keys;

    beforeAll(async () => {
      keys = await createKeys();
    });

    test('should create valid JWT token', async () => {
      const userClaims = {
        sub: '1',
        name: 'Test User',
        role: 'user'
      };

      const token = await createJwtToken(userClaims, { keys, config });

      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT format: header.payload.signature
    });

    test('should create token with correct claims', async () => {
      const userClaims = {
        sub: '123',
        name: 'John Doe',
        role: 'admin',
        email: 'john@example.com'
      };

      const token = await createJwtToken(userClaims, { keys, config });
      
      // Decode the payload (without verification for testing)
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
      
      expect(payload.sub).toBe('123');
      expect(payload.name).toBe('John Doe');
      expect(payload.role).toBe('admin');
      expect(payload.email).toBe('john@example.com');
      expect(payload.iss).toBe('test-issuer');
      expect(payload.aud).toBe('test-audience');
      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBeDefined();
      expect(payload.exp - payload.iat).toBe(3600); // TTL
    });

    test('should throw error with invalid keys', async () => {
      const invalidKeys = { kid: 'test', privateKey: null };
      
      await expect(createJwtToken(invalidKeys, { sub: '1' }))
        .rejects.toThrow();
    });

    test('should throw error with missing keys', async () => {
      await expect(createJwtToken(null, { sub: '1' }))
        .rejects.toThrow();
    });
  });
});