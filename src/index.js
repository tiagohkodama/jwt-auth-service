require('dotenv').config();

const { createKeys } = require('./lib/keys');
const buildServer = require('./server');
const { config, validateConfig } = require('./config');

/**
 * Application bootstrap
 * Following proper error handling and graceful shutdown patterns
 */
async function bootstrap() {
  try {
    console.log('Starting JWT Auth Service...');
    
    // Validate configuration
    validateConfig();
    console.log('Configuration validated');

    // Generate RSA key pair for JWT operations
    console.log('Generating RSA key pair...');
    const keys = await createKeys();
    console.log('Keys generated successfully');

    // Build and configure Express server
    console.log('Building server...');
    const app = buildServer({ keys });
    console.log('Server built successfully');

    // Start HTTP server
    const server = app.listen(config.port, () => {
      console.log(`JWT Auth Service listening on http://localhost:${config.port}`);
      console.log(`Environment: ${config.nodeEnv}`);
      console.log(`JWT Issuer: ${config.jwt.issuer}`);
      console.log(`JWT Audience: ${config.jwt.audience}`);
      console.log('');
      console.log('Available endpoints:');
      console.log(`  POST   http://localhost:${config.port}/login`);
      console.log(`  GET    http://localhost:${config.port}/me`);
      console.log(`  GET    http://localhost:${config.port}/.well-known/jwks.json`);
      console.log(`  GET    http://localhost:${config.port}/health`);
    });

    // Graceful shutdown handling
    const gracefulShutdown = (signal) => {
      console.log(`\n📡 Received ${signal}. Starting graceful shutdown...`);
      
      server.close((err) => {
        if (err) {
          console.error('Error during server shutdown:', err);
          process.exit(1);
        }
        
        console.log('Server closed successfully');
        console.log('JWT Auth Service stopped');
        process.exit(0);
      });
    };

    // Handle shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      console.error('💥 Uncaught Exception:', error);
      process.exit(1);
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
      process.exit(1);
    });

  } catch (error) {
    console.error('💥 Failed to start server:', error.message);
    process.exit(1);
  }
}

// Start the application
if (require.main === module) {
  bootstrap();
}

module.exports = { bootstrap };