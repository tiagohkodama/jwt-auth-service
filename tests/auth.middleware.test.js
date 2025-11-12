const { SignJWT } = require('jose');
const createAuthMiddleware = require('../src/middleware/auth');
const { createKeys } = require('../src/lib/keys');

// Mock config module
jest.mock('../src/config', () => ({
  config: {
    jwt: {
      issuer: 'auth-service',
      audience: 'api'
    },
    nodeEnv: 'test'
  }
}));

describe('Auth Middleware', () => {
  let keys;
  let authMiddleware;
  let mockReq;
  let mockRes;
  let mockNext;

  beforeEach(async () => {
    keys = await createKeys();
    authMiddleware = createAuthMiddleware({ keys });
    
    mockReq = {
      headers: {}
    };
    
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis()
    };
    
    mockNext = jest.fn();
  });

  test('should create middleware with valid keys', () => {
    expect(() => createAuthMiddleware({ keys })).not.toThrow();
    expect(typeof authMiddleware).toBe('function');
  });

  test('should throw error when keys are missing', () => {
    expect(() => createAuthMiddleware({})).toThrow('Keys with jwkSet are required');
    expect(() => createAuthMiddleware({ keys: {} })).toThrow('Keys with jwkSet are required');
  });

  test('should extract and verify valid JWT token', async () => {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      sub: '1',
      name: 'Test User',
      role: 'user'
    };

    const token = await new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: keys.kid })
      .setIssuer('auth-service')
      .setAudience('api')
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(keys.privateKey);

    mockReq.headers.authorization = `Bearer ${token}`;

    await authMiddleware(mockReq, mockRes, mockNext);

    expect(mockNext).toHaveBeenCalled();
    expect(mockReq.user).toEqual(expect.objectContaining(claims));
    expect(mockRes.status).not.toHaveBeenCalled();
  });

  test('should reject request without Authorization header', async () => {
    await authMiddleware(mockReq, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({ 
      error: 'missing_token',
      message: 'Authorization header with Bearer token is required'
    });
    expect(mockNext).not.toHaveBeenCalled();
  });

  test('should reject malformed Authorization header', async () => {
    mockReq.headers.authorization = 'InvalidFormat';

    await authMiddleware(mockReq, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({ 
      error: 'missing_token',
      message: 'Authorization header with Bearer token is required'
    });
    expect(mockNext).not.toHaveBeenCalled();
  });

  test('should reject invalid JWT token', async () => {
    mockReq.headers.authorization = 'Bearer invalid.jwt.token';

    await authMiddleware(mockReq, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({ 
      error: 'invalid_token',
      message: 'Invalid or expired token'
    });
    expect(mockNext).not.toHaveBeenCalled();
  });

  test('should handle case-insensitive Authorization header', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ sub: '1' })
      .setProtectedHeader({ alg: 'RS256', kid: keys.kid })
      .setIssuer('auth-service')
      .setAudience('api')
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(keys.privateKey);

    mockReq.headers.Authorization = `Bearer ${token}`;

    await authMiddleware(mockReq, mockRes, mockNext);

    expect(mockNext).toHaveBeenCalled();
    expect(mockReq.user).toBeDefined();
  });

  test('should reject expired token', async () => {
    const now = Math.floor(Date.now() / 1000);
    const expiredToken = await new SignJWT({ sub: '1' })
      .setProtectedHeader({ alg: 'RS256', kid: keys.kid })
      .setIssuer('auth-service')
      .setAudience('api')
      .setIssuedAt(now - 7200) // 2 hours ago
      .setExpirationTime(now - 3600) // 1 hour ago (expired)
      .sign(keys.privateKey);

    mockReq.headers.authorization = `Bearer ${expiredToken}`;

    await authMiddleware(mockReq, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({ 
      error: 'invalid_token',
      message: 'Invalid or expired token'
    });
    expect(mockNext).not.toHaveBeenCalled();
  });
});