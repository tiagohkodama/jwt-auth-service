const crypto = require('crypto');
const { generateKeyPair, exportJWK, createLocalJWKSet } = require('jose');

/**
 * Creates RSA key pair for JWT signing and verification
 * Following Single Responsibility Principle - only handles key generation
 * 
 * @returns {Promise<Object>} Object containing private key, kid, jwks, and jwkSet
 */
async function createKeys() {
  try {
    // Generate RSA key pair with 2048-bit modulus for RS256
    const { publicKey, privateKey } = await generateKeyPair('RS256', {
      modulusLength: 2048
    });

    // Generate unique key identifier
    const kid = crypto.randomUUID();

    // Export public key as JWK (JSON Web Key)
    const publicJwk = await exportJWK(publicKey);
    publicJwk.kid = kid;
    publicJwk.alg = 'RS256';
    publicJwk.use = 'sig'; // Key usage: signature

    // Create JWKS (JSON Web Key Set) structure
    const jwks = {
      keys: [publicJwk]
    };

    // Create JWK Set for token verification
    const jwkSet = createLocalJWKSet(jwks);

    return {
      privateKey,
      kid,
      jwks,
      jwkSet
    };
  } catch (error) {
    throw new Error(`Failed to create keys: ${error.message}`);
  }
}

module.exports = {
  createKeys
};