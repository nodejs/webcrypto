'use strict';

const assert = require('assert');
const { randomBytes } = require('crypto');

const { subtle } = require('../../../');

describe('HMAC', () => {
  it('should generate, import and export keys', async () => {
    for (const [length, keyLength] of [[undefined, 1024], [3000, 3000]]) {
      const key = await subtle.generateKey({
        name: 'HMAC',
        hash: 'SHA-384',
        length
      }, true, ['sign', 'verify']);

      assert.strictEqual(key.type, 'secret');
      assert.strictEqual(key.algorithm.name, 'HMAC');
      assert.strictEqual(key.algorithm.length, keyLength);
      assert.strictEqual(key.algorithm.hash.name, 'SHA-384');

      const expKey = await subtle.exportKey('raw', key);
      assert(Buffer.isBuffer(expKey));
      assert.strictEqual(expKey.length, keyLength >> 3);

      const impKey = await subtle.importKey('raw', expKey, {
        name: 'HMAC',
        hash: 'SHA-384'
      }, true, ['verify']);

      assert.deepStrictEqual(await subtle.exportKey('raw', impKey), expKey);
    }
  });

  it('should support JWK import and export', async () => {
    const jwk = {
      alg: 'HS256',
      ext: true,
      k: 'To82qfc2c2StSSIQ1FosEGlGHMQ-qsLMJwbpVck6fvE',
      key_ops: ['sign', 'verify'],
      kty: 'oct'
    };

    const algorithm = {
      name: 'HMAC',
      hash: 'SHA-256'
    };

    const key = await subtle.importKey('jwk', jwk, algorithm, true,
                                       ['sign', 'verify']);
    assert.strictEqual(key.algorithm.name, 'HMAC');
    assert.strictEqual(key.algorithm.length, 256);

    assert.strictEqual((await subtle.exportKey('raw', key)).toString('hex'),
                       '4e8f36a9f7367364ad492210d45a2c1069461cc43eaac2cc2706e' +
                       '955c93a7ef1');
    assert.deepStrictEqual(await subtle.exportKey('jwk', key), jwk);
  });

  it('should sign and verify data', async () => {
    const key = await subtle.generateKey({
      name: 'HMAC',
      hash: 'SHA-256'
    }, false, ['sign', 'verify']);

    const data = randomBytes(200);
    const signature = await subtle.sign('HMAC', key, data);

    const ok = await subtle.verify('HMAC', key, signature, data);
    assert.strictEqual(ok, true);
  });

  it('should verify externally signed data', async () => {
    const keyData = '99fc199e37c3a4ba9b15ba215758e2f55df4debc3f5aeffa45d4cb84' +
                    '6328b1e297092a076efa70fa414da741d945d2defa9c4c5fa44e5222' +
                    'e4548c43e7c35e82';
    const keyBuffer = Buffer.from(keyData, 'hex');
    const key = await subtle.importKey('raw', keyBuffer, {
      name: 'HMAC',
      hash: 'SHA-256'
    }, false, ['verify']);

    const data = Buffer.from('0a0b0c0d0e0f', 'hex');
    const signatureData = 'f4c0917359ed070531cc079660b9e88541073c7d31ff417be1' +
                          'fc6c7d5c5aa94f';
    const signature = Buffer.from(signatureData, 'hex');

    const ok = await subtle.verify('HMAC', key, signature, data);
    assert.strictEqual(ok, true);
  });
});
