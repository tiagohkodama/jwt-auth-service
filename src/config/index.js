/**
 * Configuration module following Single Responsibility Principle
 * Centralizes all environment variable handling
 */

const config = {
  // Server configuration
  port: Number(process.env.PORT) || 3000,
  
  // JWT configuration
  jwt: {
    issuer: process.env.ISSUER || 'auth-service',
    audience: process.env.AUDIENCE || 'api',
    ttlSeconds: Number(process.env.TOKEN_TTL_SECONDS) || 3600
  },
  
  // Authentication configuration
  auth: {
    username: process.env.LOGIN_USERNAME || 'admin',
    password: process.env.LOGIN_PASSWORD || 'secret'
  },
  
  // Environment
  nodeEnv: process.env.NODE_ENV || 'development',
  
  // Logging
  logLevel: process.env.LOG_LEVEL || 'info'
};

/**
 * Validates required configuration
 * @throws {Error} If required configuration is missing
 */
function validateConfig() {
  const required = [
    'port',
    'jwt.issuer',
    'jwt.audience',
    'auth.username',
    'auth.password'
  ];
  
  for (const key of required) {
    const value = key.split('.').reduce((obj, k) => obj?.[k], config);

    if (value === undefined || value === null || value === '') {
      throw new Error(`Missing required configuration: ${key}`);
    }
  }
}

module.exports = {
  config,
  validateConfig
};