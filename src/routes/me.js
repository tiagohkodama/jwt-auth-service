/**
 * Creates user profile routes
 * Following Single Responsibility Principle
 * 
 * @param {Object} dependencies - Dependencies object
 * @param {Object} dependencies.app - Express app instance
 * @param {Function} dependencies.authMiddleware - Authentication middleware
 */
function createMeRoutes({ app, authMiddleware }) {
  if (!app || !authMiddleware) {
    throw new Error('App and authMiddleware are required dependencies');
  }

  /**
   * GET /me - Returns current user profile from JWT claims
   * Protected route that requires valid JWT token
   * Following RESTful conventions
   */
  app.get('/me', authMiddleware, (req, res) => {
    try {
      // Extract relevant claims from JWT payload
      // req.user is populated by auth middleware
      const {
        sub,
        name,
        role,
        iss,
        aud,
        iat,
        exp
      } = req.user || {};

      // Return user profile
      // Following principle of least privilege - only return necessary data
      const userProfile = {
        sub,
        name,
        role,
        iss,
        aud,
        iat,
        exp
      };

      return res.json(userProfile);

    } catch (error) {
      console.error('Profile retrieval error:', error);
      
      return res.status(500).json({
        error: 'internal_server_error',
        message: 'An error occurred while retrieving user profile'
      });
    }
  });
}

module.exports = createMeRoutes;