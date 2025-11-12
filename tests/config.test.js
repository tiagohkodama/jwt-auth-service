describe('Configuration Module', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    // Reset environment variables and clear module cache
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe('Default Configuration', () => {
    test('should use default values when environment variables are not set', () => {
      // Clear relevant env vars
      delete process.env.PORT;
      delete process.env.ISSUER;
      delete process.env.AUDIENCE;
      delete process.env.LOGIN_USERNAME;
      delete process.env.LOGIN_PASSWORD;
      delete process.env.TOKEN_TTL_SECONDS;
      delete process.env.NODE_ENV;
      delete process.env.LOG_LEVEL;

      const { config } = require('../src/config');

      expect(config.port).toBe(3000);
      expect(config.jwt.issuer).toBe('auth-service');
      expect(config.jwt.audience).toBe('api');
      expect(config.jwt.ttlSeconds).toBe(3600);
      expect(config.auth.username).toBe('admin');
      expect(config.auth.password).toBe('secret');
      expect(config.nodeEnv).toBe('development');
      expect(config.logLevel).toBe('info');
    });
  });

  describe('Environment Variable Override', () => {
    test('should use environment variables when set', () => {
      process.env.PORT = '8080';
      process.env.ISSUER = 'test-issuer';
      process.env.AUDIENCE = 'test-audience';
      process.env.LOGIN_USERNAME = 'testuser';
      process.env.LOGIN_PASSWORD = 'testpass';
      process.env.TOKEN_TTL_SECONDS = '7200';
      process.env.NODE_ENV = 'production';
      process.env.LOG_LEVEL = 'debug';

      const { config } = require('../src/config');

      expect(config.port).toBe(8080);
      expect(config.jwt.issuer).toBe('test-issuer');
      expect(config.jwt.audience).toBe('test-audience');
      expect(config.jwt.ttlSeconds).toBe(7200);
      expect(config.auth.username).toBe('testuser');
      expect(config.auth.password).toBe('testpass');
      expect(config.nodeEnv).toBe('production');
      expect(config.logLevel).toBe('debug');
    });

    test('should handle non-numeric PORT gracefully', () => {
      process.env.PORT = 'not-a-number';
      
      const { config } = require('../src/config');
      
      expect(config.port).toBe(3000); // Should fallback to default
    });

    test('should handle non-numeric TOKEN_TTL_SECONDS gracefully', () => {
      process.env.TOKEN_TTL_SECONDS = 'not-a-number';
      
      const { config } = require('../src/config');
      
      expect(config.jwt.ttlSeconds).toBe(3600); // Should fallback to default
    });

    test('should handle negative values', () => {
      process.env.PORT = '-1';
      process.env.TOKEN_TTL_SECONDS = '-3600';
      
      const { config } = require('../src/config');
      
      expect(config.port).toBe(-1);
      expect(config.jwt.ttlSeconds).toBe(-3600);
    });
  });

  describe('Configuration Validation', () => {
    test('should validate configuration successfully with all required values', () => {
      process.env.PORT = '3000';
      process.env.ISSUER = 'auth-service';
      process.env.AUDIENCE = 'api';
      process.env.LOGIN_USERNAME = 'admin';
      process.env.LOGIN_PASSWORD = 'secret';

      const { validateConfig } = require('../src/config');

      expect(() => validateConfig()).not.toThrow();
    });

    test('should throw error when port is missing', () => {
      delete process.env.PORT;
      
      const { config, validateConfig } = require('../src/config');
      // Manually set port to undefined to test validation
      config.port = undefined;

      expect(() => validateConfig()).toThrow('Missing required configuration: port');
    });

    test('should throw error when username is null', () => {
      const { config, validateConfig } = require('../src/config');
      config.auth.username = null;

      expect(() => validateConfig()).toThrow('Missing required configuration: auth.username');
    });

    test('should throw error when password is undefined', () => {
      const { config, validateConfig } = require('../src/config');
      config.auth.password = undefined;

      expect(() => validateConfig()).toThrow('Missing required configuration: auth.password');
    });

    test('should handle nested property validation correctly', () => {
      const { config, validateConfig } = require('../src/config');
      
      // Test that nested properties are validated correctly
      config.jwt = null;
      
      expect(() => validateConfig()).toThrow('Missing required configuration: jwt.issuer');
    });
  });

  describe('Configuration Structure', () => {
    test('should have correct configuration structure', () => {
      const { config } = require('../src/config');

      expect(config).toHaveProperty('port');
      expect(config).toHaveProperty('jwt');
      expect(config).toHaveProperty('auth');
      expect(config).toHaveProperty('nodeEnv');
      expect(config).toHaveProperty('logLevel');

      expect(config.jwt).toHaveProperty('issuer');
      expect(config.jwt).toHaveProperty('audience');
      expect(config.jwt).toHaveProperty('ttlSeconds');

      expect(config.auth).toHaveProperty('username');
      expect(config.auth).toHaveProperty('password');
    });

    test('should export both config and validateConfig', () => {
      const configModule = require('../src/config');

      expect(configModule).toHaveProperty('config');
      expect(configModule).toHaveProperty('validateConfig');
      expect(typeof configModule.validateConfig).toBe('function');
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty string environment variables', () => {
      process.env.PORT = '';
      process.env.ISSUER = '';
      process.env.AUDIENCE = '';
      process.env.LOGIN_USERNAME = '';
      process.env.LOGIN_PASSWORD = '';
      process.env.TOKEN_TTL_SECONDS = '';
      process.env.NODE_ENV = '';
      process.env.LOG_LEVEL = '';

      const { config } = require('../src/config');

      // Should use defaults for empty strings
      expect(config.port).toBe(3000);
      expect(config.jwt.issuer).toBe('auth-service');
      expect(config.jwt.audience).toBe('api');
      expect(config.auth.username).toBe('admin');
      expect(config.auth.password).toBe('secret');
      expect(config.jwt.ttlSeconds).toBe(3600);
      expect(config.nodeEnv).toBe('development');
      expect(config.logLevel).toBe('info');
    });

    test('should handle whitespace-only environment variables', () => {
      process.env.ISSUER = '   ';
      process.env.AUDIENCE = '\t\n';
      process.env.LOGIN_USERNAME = '  \t  ';
      process.env.LOGIN_PASSWORD = '\n\n';

      const { config } = require('../src/config');

      // Whitespace values should be preserved (not treated as empty)
      expect(config.jwt.issuer).toBe('   ');
      expect(config.jwt.audience).toBe('\t\n');
      expect(config.auth.username).toBe('  \t  ');
      expect(config.auth.password).toBe('\n\n');
    });

    test('should handle very large numeric values', () => {
      process.env.PORT = '999999';
      process.env.TOKEN_TTL_SECONDS = '31536000'; // 1 year

      const { config } = require('../src/config');

      expect(config.port).toBe(999999);
      expect(config.jwt.ttlSeconds).toBe(31536000);
    });
  });
});