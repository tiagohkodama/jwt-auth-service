const express = require('express');
const helmet = require('helmet');
const { config } = require('./config');
const createAuthRoutes = require('./routes/auth');
const createMeRoutes = require('./routes/me');
const createAuthMiddleware = require('./middleware/auth');

function buildServer({ keys } = {}) {
  if (!keys) {
    throw new Error('Keys are required to build server');
  }

  const app = express();

  app.disable('x-powered-by');
  app.use(helmet());

  const jsonLimit = '10mb';
  app.use(express.json({ limit: jsonLimit }));
  app.use(express.urlencoded({ extended: true, limit: jsonLimit }));
  app.get('/health', (req, res) => {
    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
    });
  });

  app.get('/.well-known/jwks.json', (req, res, next) => {
    try {
      if (!keys.jwks) {
        throw new Error('JWKS not available');
      }
      res.set('Content-Type', 'application/json');
      res.set('Cache-Control', 'public, max-age=300, immutable');
      res.status(200).json(keys.jwks);
    } catch (err) {
      next(err);
    }
  });

  const authMiddleware = createAuthMiddleware({ keys, config });
  createAuthRoutes({ app, keys });
  createMeRoutes({ app, authMiddleware });

  app.use((req, res) => {
    res.status(404).json({
      error: 'not_found',
      message: `${req.method} ${req.path} not found`,
    });
  });

  app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);

    const status =
      error.statusCode ||
      error.status ||
      (error.type === 'entity.too.large' ? 413 : 500);

    const errorCode =
      status === 400
        ? 'bad_request'
        : status === 413
        ? 'payload_too_large'
        : 'internal_server_error';

    const message =
      config.nodeEnv === 'production'
        ? 'An unexpected error occurred'
        : error.message || 'Unknown error';

    res.status(status).json({ error: errorCode, message });
  });

  return app;
}

module.exports = buildServer;