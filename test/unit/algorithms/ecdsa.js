'use strict';

const assert = require('assert');
const { randomBytes } = require('crypto');

const { crypto: { subtle } } = require('../../../');

// Disables timeouts for tests that involve key pair generation.
const NO_TIMEOUT = 0;

describe('ECDSA', () => {
  it('should generate, import and export keys', async () => {
    const { publicKey, privateKey } = await subtle.generateKey({
      name: 'ECDSA',
      namedCurve: 'P-256'
    }, true, ['sign', 'verify']);

    assert.strictEqual(publicKey.type, 'public');
    assert.strictEqual(privateKey.type, 'private');
    for (const key of [publicKey, privateKey]) {
      assert.strictEqual(key.algorithm.name, 'ECDSA');
      assert.strictEqual(key.algorithm.namedCurve, 'P-256');
    }

    const expPublicKey = await subtle.exportKey('spki', publicKey);
    assert(Buffer.isBuffer(expPublicKey));
    const expPrivateKey = await subtle.exportKey('pkcs8', privateKey);
    assert(Buffer.isBuffer(expPrivateKey));

    const impPublicKey = await subtle.importKey('spki', expPublicKey, {
      name: 'ECDSA',
      hash: 'SHA-384'
    }, true, ['verify']);
    const impPrivateKey = await subtle.importKey('pkcs8', expPrivateKey, {
      name: 'ECDSA',
      hash: 'SHA-384'
    }, true, ['sign']);

    assert.deepStrictEqual(await subtle.exportKey('spki', impPublicKey),
                           expPublicKey);
    assert.deepStrictEqual(await subtle.exportKey('pkcs8', impPrivateKey),
                           expPrivateKey);
  })
  .timeout(NO_TIMEOUT);

  it('should sign and verify data', async () => {
    async function test(namedCurve, signatureLength) {
      const { privateKey, publicKey } = await subtle.generateKey({
        name: 'ECDSA',
        namedCurve
      }, false, ['sign', 'verify']);

      const data = randomBytes(200);
      for (const hash of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
        const signature = await subtle.sign({
          name: 'ECDSA',
          hash
        }, privateKey, data);
        assert.strictEqual(signature.length, signatureLength);

        let ok = await subtle.verify({
          name: 'ECDSA',
          hash
        }, publicKey, signature, data);
        assert.strictEqual(ok, true);

        signature[Math.floor(signature.length * Math.random())] ^= 1;

        ok = await subtle.verify({
          name: 'ECDSA',
          hash
        }, publicKey, signature, data);
        assert.strictEqual(ok, false);
      }
    }

    return Promise.all([
      test('P-256', 2 * 32),
      test('P-384', 2 * 48),
      test('P-521', 2 * 66)
    ]);
  })
  .timeout(NO_TIMEOUT);

  it('should verify externally signed data', async () => {
    const publicKeyData = '3076301006072a8648ce3d020106052b810400220362000476' +
                          'ece47b2ab001a109f741f9fcd7fbe9cbfd3b6abbac626bd1fb' +
                          'eca18fc700adc612339a732ee4621a129dfdc22940011d17ff' +
                          '94a06e8aa55b6a62c3014032aeefc099d455921a0072d26a45' +
                          'b787bd327beb2846f70657268d2485423720be4b';
    const publicKeyBuffer = Buffer.from(publicKeyData, 'hex');
    const publicKey = await subtle.importKey('spki', publicKeyBuffer, {
      name: 'ECDSA',
      namedCurve: 'P-384'
    }, false, ['verify']);

    const data = Buffer.from('0a0b0c0d0e0f', 'hex');
    const signatureData = '5ec17d2611a28d72e448826ba3b3fb7ef041275c5727b05d38' +
                          '8fb435b2897a9047d9f02ade37908e6f81e1419fd671978881' +
                          '9887f0fd830dd02ecc66051e14512fdba0f51fb3e58629210d' +
                          '136a48944f411649874cfb29498161c6327a7d4c3d';
    const signature = Buffer.from(signatureData, 'hex');

    const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-512' },
                                   publicKey, signature, data);
    assert.strictEqual(ok, true);
  });
});
