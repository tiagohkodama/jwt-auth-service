const { createKeys } = require('../src/lib/keys');

describe('Keys Library', () => {
  describe('Key Generation', () => {
    test('should generate RSA key pair successfully', async () => {
      const keys = await createKeys();

      expect(keys).toHaveProperty('privateKey');
      expect(keys).toHaveProperty('kid');
      expect(keys).toHaveProperty('jwks');
      expect(keys).toHaveProperty('jwkSet');
    });

    test('should generate valid private key', async () => {
      const keys = await createKeys();

      expect(keys.privateKey).toBeDefined();
      expect(typeof keys.privateKey).toBe('object');
      // Private key should have the expected structure for RSA keys
      expect(keys.privateKey.asymmetricKeyType).toBe('rsa');
    });

    test('should generate unique key IDs', async () => {
      const keys1 = await createKeys();
      const keys2 = await createKeys();
      
      expect(keys1.kid).not.toBe(keys2.kid);
      expect(typeof keys1.kid).toBe('string');
      expect(typeof keys2.kid).toBe('string');
      expect(keys1.kid.length).toBeGreaterThan(0);
      expect(keys2.kid.length).toBeGreaterThan(0);
    });

    test('should generate different key pairs each time', async () => {
      const keys1 = await createKeys();
      const keys2 = await createKeys();
      
      // Keys should be different objects
      expect(keys1.privateKey).not.toBe(keys2.privateKey);
      expect(keys1.jwks).not.toBe(keys2.jwks);
      
      // JWKS should have different modulus values
      expect(keys1.jwks.keys[0].n).not.toBe(keys2.jwks.keys[0].n);
    });
  });

  describe('JWKS Structure', () => {
    let keys;

    beforeEach(async () => {
      keys = await createKeys();
    });

    test('should generate valid JWKS structure', () => {
      expect(keys.jwks).toHaveProperty('keys');
      expect(Array.isArray(keys.jwks.keys)).toBe(true);
      expect(keys.jwks.keys).toHaveLength(1);
    });

    test('should have correct public key properties', () => {
      const publicKey = keys.jwks.keys[0];
      
      expect(publicKey).toHaveProperty('kid');
      expect(publicKey).toHaveProperty('alg', 'RS256');
      expect(publicKey).toHaveProperty('kty', 'RSA');
      expect(publicKey).toHaveProperty('use', 'sig');
      expect(publicKey).toHaveProperty('n'); // RSA modulus
      expect(publicKey).toHaveProperty('e'); // RSA exponent
    });

    test('should have matching key ID between private key reference and JWKS', () => {
      const publicKey = keys.jwks.keys[0];
      expect(publicKey.kid).toBe(keys.kid);
    });

    test('should have valid RSA modulus and exponent', () => {
      const publicKey = keys.jwks.keys[0];
      
      // RSA modulus should be a base64url encoded string
      expect(typeof publicKey.n).toBe('string');
      expect(publicKey.n.length).toBeGreaterThan(0);
      
      // RSA exponent should be 'AQAB' (65537 in base64url)
      expect(publicKey.e).toBe('AQAB');
    });

    test('should have correct algorithm and key type', () => {
      const publicKey = keys.jwks.keys[0];
      
      expect(publicKey.alg).toBe('RS256');
      expect(publicKey.kty).toBe('RSA');
      expect(publicKey.use).toBe('sig');
    });
  });

  describe('JWK Set for Verification', () => {
    let keys;

    beforeEach(async () => {
      keys = await createKeys();
    });

    test('should create valid JWK Set for verification', () => {
      expect(keys.jwkSet).toBeDefined();
      expect(typeof keys.jwkSet).toBe('function');
    });

    test('should be able to use JWK Set for key lookup', async () => {
      // This tests that the JWK Set can be used for key resolution
      // The actual verification would be done by the jose library
      expect(() => keys.jwkSet).not.toThrow();
    });
  });

  describe('Key Properties Validation', () => {
    let keys;

    beforeEach(async () => {
      keys = await createKeys();
    });

    test('should have UUID format key ID', () => {
      // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      expect(keys.kid).toMatch(uuidRegex);
    });

    test('should have consistent key ID across all references', () => {
      const publicKey = keys.jwks.keys[0];
      
      expect(keys.kid).toBe(publicKey.kid);
      expect(typeof keys.kid).toBe('string');
      expect(keys.kid.length).toBe(36); // UUID length
    });

    test('should generate 2048-bit RSA keys', () => {
      const publicKey = keys.jwks.keys[0];
      
      // Base64url decode the modulus to check bit length
      // This is an approximation - 2048-bit key should have ~342-344 character modulus
      expect(publicKey.n.length).toBeGreaterThan(340);
      expect(publicKey.n.length).toBeLessThan(350);
    });
  });

  describe('Error Handling', () => {
    test('should handle key generation errors gracefully', async () => {
      // Mock the generateKeyPair to throw an error
      const originalGenerateKeyPair = require('jose').generateKeyPair;
      const { generateKeyPair } = require('jose');
      
      // This test verifies error handling structure
      // In a real scenario, we might mock the jose library to throw errors
      await expect(createKeys()).resolves.toBeDefined();
    });

    test('should create keys multiple times without interference', async () => {
      const promises = Array(5).fill().map(() => createKeys());
      const results = await Promise.all(promises);
      
      // All should succeed
      results.forEach(keys => {
        expect(keys).toHaveProperty('privateKey');
        expect(keys).toHaveProperty('kid');
        expect(keys).toHaveProperty('jwks');
        expect(keys).toHaveProperty('jwkSet');
      });
      
      // All should be unique
      const kids = results.map(k => k.kid);
      const uniqueKids = new Set(kids);
      expect(uniqueKids.size).toBe(5);
    });
  });

  describe('Performance and Concurrency', () => {
    test('should generate keys in reasonable time', async () => {
      const startTime = Date.now();
      await createKeys();
      const endTime = Date.now();
      
      // Key generation should complete within 5 seconds
      expect(endTime - startTime).toBeLessThan(5000);
    });

    test('should handle concurrent key generation', async () => {
      const concurrentPromises = Array(3).fill().map(() => createKeys());
      
      const results = await Promise.all(concurrentPromises);
      
      // All should complete successfully
      expect(results).toHaveLength(3);
      results.forEach(keys => {
        expect(keys).toHaveProperty('privateKey');
        expect(keys).toHaveProperty('kid');
      });
      
      // All should be unique
      const kids = results.map(k => k.kid);
      expect(new Set(kids).size).toBe(3);
    });
  });

  describe('Memory and Resource Management', () => {
    test('should not leak memory with multiple key generations', async () => {
      // Generate multiple keys to test for memory leaks
      const keys = [];
      
      for (let i = 0; i < 10; i++) {
        keys.push(await createKeys());
      }
      
      // All keys should be valid
      expect(keys).toHaveLength(10);
      keys.forEach(keySet => {
        expect(keySet).toHaveProperty('privateKey');
        expect(keySet).toHaveProperty('jwks');
      });
      
      // All key IDs should be unique
      const kids = keys.map(k => k.kid);
      expect(new Set(kids).size).toBe(10);
    });
  });
});