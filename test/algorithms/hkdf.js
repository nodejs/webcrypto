'use strict';

const assert = require('assert');

const { subtle } = require('../../');

describe('HKDF', () => {
  it('should import keys', async () => {
    const keyBuffer = Buffer.from('passphrase', 'utf8');
    const key = await subtle.importKey('raw', keyBuffer, 'HKDF', false,
                                       ['deriveBits']);
    assert.strictEqual(key.algorithm.name, 'HKDF');
    assert.strictEqual(key.type, 'secret');
    assert.strictEqual(key.extractable, false);
    assert.deepEqual(key.usages, ['deriveBits']);
  });

  it('should produce correct outputs', async () => {
    const keyBuffer = Buffer.from('passphrase', 'utf8');
    const key = await subtle.importKey('raw', keyBuffer, 'HKDF', false,
                                       ['deriveBits']);

    const bits = await subtle.deriveBits({
      name: 'HKDF',
      hash: 'SHA-384',
      salt: Buffer.from('b19a9d6d7f7d2e9e', 'hex'),
      info: Buffer.alloc(0)
    }, key, 128);

    assert(Buffer.isBuffer(bits));
    assert.strictEqual(bits.toString('hex'),
                       '4b52236af0e6516384e531e618c95b96');
  });

  it('should produce correct keys', async () => {
    const keyBuffer = Buffer.from('passphrase', 'utf8');
    const key = await subtle.importKey('raw', keyBuffer, 'HKDF', false,
                                       ['deriveKey']);

    const derivedKey = await subtle.deriveKey({
      name: 'HKDF',
      hash: 'SHA-1',
      salt: Buffer.from('b19a9d6d7f7d2e9e', 'hex'),
      info: Buffer.alloc(0)
    }, key, {
      name: 'AES-CTR',
      length: 256
    }, true, ['encrypt', 'decrypt']);

    assert.strictEqual(derivedKey.type, 'secret');

    const bits = await subtle.exportKey('raw', derivedKey);
    assert.strictEqual(bits.toString('hex'),
                       '70d38acbfd289f4869069d254e7addff' +
                       'c1eec6cf90dc0f8f1598b97828f23b3f');
  });
});
