const { SignJWT } = require('jose');
const { randomUUID } = require('crypto');
const { config } = require('../config');

function validateCredentials(creds = {}, expected) {
  const username = typeof creds?.username === 'string' ? creds.username : '';
  const password = typeof creds?.password === 'string' ? creds.password : '';
  return username === expected.username && password === expected.password;
}

async function createJwtToken(claims = {}, { keys, config }) {
  if (!keys?.privateKey || !keys?.kid) {
    throw new Error('Invalid keys for JWT creation');
  }

  const now = Math.floor(Date.now() / 1000);
  const ttl = Number(config.jwt.ttlSeconds) || 0;
  const jti = randomUUID();

  return await new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: keys.kid })
    .setIssuer(config.jwt.issuer)
    .setAudience(config.jwt.audience)
    .setIssuedAt(now)
    .setExpirationTime(now + ttl)
    .setJti(jti)
    .sign(keys.privateKey);
}

function createAuthRoutes({ app, keys }) {
  if (!app || !keys) {
    throw new Error('App and keys are required dependencies');
  }

  app.post('/login', async (req, res) => {
    try {
      const { username, password } = req.body || {};

      if (!username || !password) {
        return res.status(400).json({
          error: 'invalid_request',
          message: 'Username and password are required'
        });
      }

      if (!validateCredentials({ username, password }, config.auth)) {
        return res.status(401).json({
          error: 'invalid_credentials',
          message: 'Invalid username or password'
        });
      }

      const userClaims = {
        sub: '1',
        name: 'Admin',
        role: 'admin',
      };

      const accessToken = await createJwtToken(userClaims, { keys, config });

      return res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: config.jwt.ttlSeconds
      });

    } catch (error) {
      console.error('Login error:', error);
      
      return res.status(500).json({
        error: 'internal_server_error',
        message: 'An error occurred during authentication'
      });
    }
  });
}

module.exports = createAuthRoutes;
module.exports.validateCredentials = validateCredentials;
module.exports.createJwtToken = createJwtToken;