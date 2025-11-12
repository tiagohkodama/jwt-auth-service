const { jwtVerify } = require('jose');
const { config } = require('../config');

/**
 * Extracts Bearer token from Authorization header
 * Following Single Responsibility Principle
 * 
 * @param {Object} req - Express request object
 * @returns {string|null} JWT token or null if not found
 */
function extractBearerToken(req) {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  
  if (!authHeader) {
    return null;
  }
  
  const [type, token] = String(authHeader).trim().split(/\s+/ig);
  
  if (type !== 'Bearer' || !token) {
    return null;
  }
  
  return token;
}

/**
 * Creates JWT authentication middleware
 * Following Dependency Injection principle
 * 
 * @param {Object} dependencies - Dependencies object
 * @param {Object} dependencies.keys - Keys object with jwkSet
 * @returns {Function} Express middleware function
 */
function createAuthMiddleware({ keys }) {
  if (!keys || !keys.jwkSet) {
    throw new Error('Keys with jwkSet are required for auth middleware');
  }

  return async (req, res, next) => {
    try {
      const token = extractBearerToken(req);
      
      if (!token) {
        return res.status(401).json({ 
          error: 'missing_token',
          message: 'Authorization header with Bearer token is required'
        });
      }

      // Verify JWT token
      const { payload } = await jwtVerify(token, keys.jwkSet, {
        algorithms: ['RS256'],
        issuer: config.jwt.issuer,
        audience: config.jwt.audience
      });

      // Attach user payload to request
      req.user = payload;
      
      return next();
    } catch (error) {
      // Log error for debugging (in production, use proper logger)
      if (config.nodeEnv === 'development') {
        console.error('JWT verification failed:', error.message);
      }
      
      return res.status(401).json({ 
        error: 'invalid_token',
        message: 'Invalid or expired token'
      });
    }
  };
}

// Export both the main function and helper for testing
module.exports = createAuthMiddleware;
module.exports.extractBearerToken = extractBearerToken;