'use strict';

const assert = require('assert');
const { randomBytes } = require('crypto');

const { subtle } = require('../../../lib');

function twice(buf) {
  return Buffer.concat([buf, buf], buf.length * 2);
}

function testGenImportExport(name, keyUsages) {
  return async () => {
    const key1 = await subtle.generateKey({ name, length: 192 }, true,
                                          keyUsages);
    assert.strictEqual(key1.algorithm.name, name);
    const key2 = await subtle.generateKey({ name, length: 192 }, true,
                                          keyUsages);
    assert.strictEqual(key2.algorithm.name, name);
    const key3 = await subtle.generateKey({ name, length: 256 }, true,
                                          keyUsages);
    assert.strictEqual(key3.algorithm.name, name);

    const expKey1 = await subtle.exportKey('raw', key1);
    assert(Buffer.isBuffer(expKey1));
    assert.strictEqual(expKey1.length, 24);
    const expKey2 = await subtle.exportKey('raw', key2);
    assert(Buffer.isBuffer(expKey2));
    assert.strictEqual(expKey2.length, 24);
    const expKey3 = await subtle.exportKey('raw', key3);
    assert(Buffer.isBuffer(expKey3));
    assert.strictEqual(expKey3.length, 32);

    assert.notDeepStrictEqual(expKey1, expKey2);

    const impKey1 = await subtle.importKey('raw', expKey1, name, true,
                                           keyUsages);
    const impKey2 = await subtle.importKey('raw', expKey2, name, true,
                                           keyUsages);
    const impKey3 = await subtle.importKey('raw', expKey3, name, true,
                                           keyUsages);

    assert.deepStrictEqual(await subtle.exportKey('raw', impKey1), expKey1);
    assert.deepStrictEqual(await subtle.exportKey('raw', impKey2), expKey2);
    assert.deepStrictEqual(await subtle.exportKey('raw', impKey3), expKey3);
  };
}

function testJsonWebKeys(algorithmName, jwkAlgorithmSuffix, keyUsages) {
  async function test(jwk, hexKey, length) {
    const key = await subtle.importKey('jwk', jwk, algorithmName, true,
                                       keyUsages);
    assert.strictEqual(key.algorithm.name, algorithmName);
    assert.strictEqual(key.algorithm.length, length);

    assert.strictEqual((await subtle.exportKey('raw', key)).toString('hex'),
                       hexKey);
    assert.deepStrictEqual(await subtle.exportKey('jwk', key), jwk);
  }

  return async () => {
    return Promise.all([
      // Example A.3 from RFC7517.
      test({
        kty: 'oct',
        alg: `A128${jwkAlgorithmSuffix}`,
        k: 'GawgguFyGrWKav7AX4VKUg',
        ext: true,
        key_ops: keyUsages
      }, '19ac2082e1721ab58a6afec05f854a52', 128),

      // Generated in Mozilla Firefox.
      test({
        alg: `A192${jwkAlgorithmSuffix}`,
        ext: true,
        k: 'bOHt12k8byt-XKHo9kXY_1skBP10eJGC',
        key_ops: keyUsages,
        kty: 'oct'
      }, '6ce1edd7693c6f2b7e5ca1e8f645d8ff5b2404fd74789182', 192)
    ]);
  };
}

describe('AES-CTR', () => {
  it('should generate, import and export keys',
     testGenImportExport('AES-CTR', ['encrypt', 'decrypt']));

  it('should support JWK import and export',
     testJsonWebKeys('AES-CTR', 'CTR', ['encrypt', 'decrypt']));

  it('should encrypt and decrypt', async () => {
    const keyData = Buffer.from('36adfe538cc234279e4cbb29e1f27af5', 'hex');
    const counter = Buffer.from('2159e5bd415791990e52b5c825572994', 'hex');
    const length = 128;

    const key = await subtle.importKey('raw', keyData, 'AES-CTR', false,
                                       ['encrypt', 'decrypt']);

    const plaintext = Buffer.from('Hello WebCrypto!', 'utf8');
    const ciphertext = await subtle.encrypt({
      name: 'AES-CTR',
      counter,
      length
    }, key, plaintext);
    assert.strictEqual(ciphertext.toString('hex'),
                       '0bdbe0f2de637f43b9d86f8bb0ba5f05');

    const deciphered = await subtle.decrypt({
      name: 'AES-CTR',
      counter,
      length
    }, key, ciphertext);
    assert.deepStrictEqual(deciphered, plaintext);
  });

  it('should handle the "length" parameter', async () => {
    const blockSize = 16;
    const key = await subtle.generateKey({ name: 'AES-CTR', length: 192 },
                                         false, ['encrypt', 'decrypt']);

    // In this case, only the last bit of the IV will be flipped between blocks,
    // meaning that every second block will be XOR'd with the same bit stream.
    const plaintext = twice(randomBytes(2 * blockSize));
    let counter = randomBytes(blockSize);
    let length = 1;
    let ciphertext = await subtle.encrypt({ name: 'AES-CTR', counter, length },
                                          key, plaintext);
    assert.strictEqual(ciphertext.length, 4 * blockSize);
    const encryptedFirstHalf = ciphertext.slice(0, 2 * blockSize);
    const encryptedSecondHalf = ciphertext.slice(2 * blockSize);
    assert.deepStrictEqual(encryptedFirstHalf, encryptedSecondHalf);

    let decrypted = await subtle.decrypt({ name: 'AES-CTR', counter, length },
                                         key, ciphertext);
    assert.deepStrictEqual(decrypted, plaintext);

    // This is slightly more tricky: We allow incrementing the last 127 bits,
    // which will not lead to any repetitions that we could test for. However,
    // we can pick an IV that will cause an overflow, which would usually cause
    // the MSB to be flipped, but since the MSB is not within the last 127 bits,
    // this cannot happen. We just need to verify that the second block was
    // encrypted using the correct IV (with an unmodified MSB).
    counter = Buffer.from('7fffffffffffffffffffffffffffffff', 'hex');
    length = 127;
    ciphertext = await subtle.encrypt({ name: 'AES-CTR', counter, length },
                                      key, plaintext);
    const expectedIV = Buffer.from('00000000000000000000000000000000', 'hex');
    const expectedSecondBlock = await subtle.encrypt({
      name: 'AES-CTR',
      counter: expectedIV,
      length: 128
    }, key, plaintext.slice(blockSize, 2 * blockSize));
    assert.deepStrictEqual(ciphertext.slice(blockSize, 2 * blockSize),
                           expectedSecondBlock);

    decrypted = await subtle.decrypt({ name: 'AES-CTR', counter, length }, key,
                                     ciphertext);
    assert.deepStrictEqual(decrypted, plaintext);
  });
});

describe('AES-CBC', () => {
  it('should generate, import and export keys',
     testGenImportExport('AES-CBC', ['encrypt', 'decrypt']));

  it('should support JWK import and export',
     testJsonWebKeys('AES-CBC', 'CBC', ['encrypt', 'decrypt']));

  it('should encrypt and decrypt', async () => {
    const keyData = Buffer.from('36adfe538cc234279e4cbb29e1f27af5', 'hex');
    const iv = Buffer.from('2159e5bd415791990e52b5c825572994', 'hex');

    const key = await subtle.importKey('raw', keyData, 'AES-CBC', false,
                                       ['encrypt', 'decrypt']);

    const plaintext = Buffer.from('Hello WebCrypto!', 'utf8');
    const ciphertext = await subtle.encrypt({
      name: 'AES-CBC',
      iv
    }, key, plaintext);
    assert.strictEqual(ciphertext.toString('hex'),
                       '8bb6173879b0f7a8899397e0fde3a3c88c69e86b18' +
                       'eb74f8629be60287c89552');

    const deciphered = await subtle.decrypt({
      name: 'AES-CBC',
      iv
    }, key, ciphertext);
    assert.deepStrictEqual(deciphered, plaintext);
  });
});

describe('AES-GCM', () => {
  it('should generate, import and export keys',
     testGenImportExport('AES-GCM', ['encrypt', 'decrypt']));

  it('should support JWK import and export',
     testJsonWebKeys('AES-GCM', 'GCM', ['encrypt', 'decrypt']));

  it('should encrypt and decrypt', async () => {
    const keyData = Buffer.from('36adfe538cc234279e4cbb29e1f27af5', 'hex');
    const iv = Buffer.from('2159e5bd415791990e52b5c825572994', 'hex');

    const key = await subtle.importKey('raw', keyData, 'AES-GCM', false,
                                       ['encrypt', 'decrypt']);

    const plaintext = Buffer.from('Hello WebCrypto!', 'utf8');
    const ciphertext = await subtle.encrypt({
      name: 'AES-GCM',
      iv
    }, key, plaintext);
    assert.strictEqual(ciphertext.toString('hex'),
                       '7080337fe4a1f8d8d96fa061ccfdb8cda6dacbf3f2' +
                       '7ef1dc85190feddc4befdd');

    const deciphered = await subtle.decrypt({
      name: 'AES-GCM',
      iv
    }, key, ciphertext);
    assert.deepStrictEqual(deciphered, plaintext);
  });

  it('should handle the "tagLength" parameter', async () => {
    const keyData = Buffer.from('36adfe538cc234279e4cbb29e1f27af5', 'hex');
    const iv = Buffer.from('2159e5bd415791990e52b5c825572994', 'hex');

    const key = await subtle.importKey('raw', keyData, 'AES-GCM', false,
                                       ['encrypt', 'decrypt']);

    const plaintext = Buffer.from('Hello WebCrypto!', 'utf8');
    const ciphertext = await subtle.encrypt({
      name: 'AES-GCM',
      iv,
      tagLength: 112
    }, key, plaintext);
    assert.strictEqual(ciphertext.toString('hex'),
                       '7080337fe4a1f8d8d96fa061ccfdb8cda6dacbf3f2' +
                       '7ef1dc85190feddc4b');

    const deciphered = await subtle.decrypt({
      name: 'AES-GCM',
      iv,
      tagLength: 112
    }, key, ciphertext);
    assert.deepStrictEqual(deciphered, plaintext);
  });

  it('should support all IV lengths', async () => {
    const keyData = Buffer.from('36adfe538cc234279e4cbb29e1f27af5', 'hex');
    const iv = twice(Buffer.from('2159e5bd415791990e52b5c825572994', 'hex'));

    const key = await subtle.importKey('raw', keyData, 'AES-GCM', false,
                                       ['encrypt', 'decrypt']);

    const plaintext = Buffer.from('Hello WebCrypto!', 'utf8');
    const ciphertext = await subtle.encrypt({
      name: 'AES-GCM',
      iv,
      tagLength: 112
    }, key, plaintext);
    assert.strictEqual(ciphertext.toString('hex'),
                       '2f136ce56f36acf081476d227c0fb89ed4e0fcd07b' +
                       '3b8de9d412f99a2c2d');

    const deciphered = await subtle.decrypt({
      name: 'AES-GCM',
      iv,
      tagLength: 112
    }, key, ciphertext);
    assert.deepStrictEqual(deciphered, plaintext);
  });
});

describe('AES-KW', () => {
  it('should generate, import and export keys',
     testGenImportExport('AES-KW', ['wrapKey', 'unwrapKey']));

  it('should support JWK import and export',
     testJsonWebKeys('AES-KW', 'KW', ['wrapKey', 'unwrapKey']));

  it('should wrap and unwrap keys', async () => {
    const wrappingKey = await subtle.generateKey({
      name: 'AES-KW',
      length: 192
    }, false, ['wrapKey', 'unwrapKey']);
    const keyToWrap = await subtle.generateKey({
      name: 'AES-CBC',
      length: 256
    }, true, ['encrypt', 'decrypt']);
    const wrappedKey = await subtle.wrapKey('raw', keyToWrap, wrappingKey,
                                            'AES-KW');
    assert(Buffer.isBuffer(wrappedKey));
    assert.strictEqual(wrappedKey.length, (256 + 64) / 8);

    const unwrappedKey = await subtle.unwrapKey('raw', wrappedKey, wrappingKey,
                                                'AES-KW', 'AES-CBC', true,
                                                ['encrypt', 'decrypt']);
    assert.deepStrictEqual(await subtle.exportKey('raw', unwrappedKey),
                           await subtle.exportKey('raw', keyToWrap));
  });
});
