'use strict';

const assert = require('assert');

const { subtle } = require('../../');

describe('ECDH', () => {
  it('should generate/import/export keys and derive bits/keys', async () => {
    const alice = await subtle.generateKey({
      name: 'ECDH',
      namedCurve: 'P-256'
    }, true, ['deriveBits']);

    const bob = await subtle.generateKey({
      name: 'ECDH',
      namedCurve: 'P-256'
    }, true, ['deriveBits', 'deriveKey']);

    const aliceSecret = await subtle.deriveBits({
      name: 'ECDH',
      public: bob.publicKey
    }, alice.privateKey, 256);

    const alicesPublicKeys = [
      alice.publicKey,
      ...await Promise.all(['raw', 'jwk'].map(async (format) => {
        const exportedKey = await subtle.exportKey(format, alice.publicKey);
        return subtle.importKey(format, exportedKey, {
          name: 'ECDH',
          namedCurve: 'P-256'
        }, false, []);
      }))
    ];

    for (const publicKey of alicesPublicKeys) {
      const bobSecret = await subtle.deriveBits({
        name: 'ECDH',
        public: publicKey
      }, bob.privateKey, 256);

      assert.deepStrictEqual(aliceSecret, bobSecret);

      const bobSecretKey = await subtle.deriveKey({
        name: 'ECDH',
        public: publicKey
      }, bob.privateKey, {
        name: 'AES-CBC',
        length: 256
      }, true, []);

      const exportedSecretKey = await subtle.exportKey('raw', bobSecretKey);
      assert.deepStrictEqual(aliceSecret, exportedSecretKey);
    }
  });

  it('should produce correct outputs', async () => {
    const privateJwk = {
      'crv': 'P-256',
      'd': 'ffSStIvU_HD67uYn1oFI-s6j1zRzrT0_s0QKJakFjEs',
      'ext': true,
      'key_ops': ['deriveBits'],
      'kty': 'EC',
      'x': 'KPmyBVeEaO6sBljE-WP6mDnkSkHGczqXW6U3n1rg1RA',
      'y': 'Y9fUgdVgvttDtbeaUbqUr2WZnRsSgnVEIG7HpsnXegw'
    };
    const publicJwk = {
      'crv': 'P-256',
      'ext': true,
      'key_ops': [],
      'kty': 'EC',
      'x': 'SBqgFzkY5nbJQlIuDjRa5iAZCazdEV0ntTYHnGnRStU',
      'y': '_OJnPBT_sY6UhJnk49b5Hgoi5txvm1_PY-ldrqGFYc8'
    };

    const privateKey = await subtle.importKey('jwk', privateJwk, {
      name: 'ECDH',
      namedCurve: 'P-256'
    }, true, ['deriveBits']);
    const publicKey = await subtle.importKey('jwk', publicJwk, {
      name: 'ECDH',
      namedCurve: 'P-256'
    }, true, []);

    assert.strictEqual(privateKey.type, 'private');
    assert.deepStrictEqual(await subtle.exportKey('jwk', privateKey),
                           privateJwk);

    assert.strictEqual(publicKey.type, 'public');
    assert.deepStrictEqual(await subtle.exportKey('jwk', publicKey), publicJwk);

    const bits = await subtle.deriveBits({
      name: 'ECDH',
      public: publicKey
    }, privateKey, 256);

    assert(Buffer.isBuffer(bits));
    assert.strictEqual(bits.toString('hex'),
                       '594f5309643afa707a9782a6faae1677' +
                       '6ef7577af8fce48634efdd93c5a1caf0');
  });
});
