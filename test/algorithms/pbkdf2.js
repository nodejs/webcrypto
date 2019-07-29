import assert from 'assert';

import { subtle } from '../../lib';

describe('PBKDF2', () => {
  it('should import keys', async () => {
    const keyBuffer = Buffer.from('passphrase', 'utf8');
    const key = await subtle.importKey('raw', keyBuffer, 'PBKDF2', false,
                                       ['deriveBits']);
    assert.strictEqual(key.algorithm.name, 'PBKDF2');
    assert.strictEqual(key.type, 'secret');
    assert.strictEqual(key.extractable, false);
    assert.deepEqual(key.usages, ['deriveBits']);
  });

  it('should produce correct outputs', async () => {
    const keyBuffer = Buffer.from('passphrase', 'utf8');
    const key = await subtle.importKey('raw', keyBuffer, 'PBKDF2', false,
                                       ['deriveBits']);

    const bits = await subtle.deriveBits({
      name: 'PBKDF2',
      iterations: 1000,
      hash: 'SHA-512',
      salt: Buffer.from('Hello world', 'utf8')
    }, key, 256);

    assert(Buffer.isBuffer(bits));
    assert.strictEqual(bits.toString('hex'),
                       '5552743c1053eeb1c91c1b33c806efd6' +
                       '2585e90c932bcdad4814a572537bdef5');
  });

  it('should produce correct keys', async () => {
    const keyBuffer = Buffer.from('passphrase', 'utf8');
    const key = await subtle.importKey('raw', keyBuffer, 'PBKDF2', false,
                                       ['deriveKey']);

    const derivedKey = await subtle.deriveKey({
      name: 'PBKDF2',
      iterations: 1000,
      hash: 'SHA-512',
      salt: Buffer.from('Hello world', 'utf8')
    }, key, {
      name: 'AES-CTR',
      length: 256
    }, true, ['encrypt', 'decrypt']);

    assert.strictEqual(derivedKey.type, 'secret');

    const bits = await subtle.exportKey('raw', derivedKey);
    assert.strictEqual(bits.toString('hex'),
                       '5552743c1053eeb1c91c1b33c806efd6' +
                       '2585e90c932bcdad4814a572537bdef5');
  });
});
