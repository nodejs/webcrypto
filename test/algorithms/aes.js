'use strict';

const assert = require('assert');
const { randomBytes } = require('crypto');

const { subtle } = require('../../');

function twice(buf) {
  return Buffer.concat([buf, buf], buf.length * 2);
}

function testGenImportExport(name) {
  return async () => {
    const key1 = await subtle.generateKey({ name, length: 192 }, true,
                                          ['encrypt', 'decrypt']);
    assert.strictEqual(key1.algorithm.name, name);
    const key2 = await subtle.generateKey({ name, length: 192 }, true,
                                          ['encrypt', 'decrypt']);
    assert.strictEqual(key2.algorithm.name, name);
    const key3 = await subtle.generateKey({ name, length: 256 }, true,
                                          ['encrypt', 'decrypt']);
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

    assert.notDeepEqual(expKey1, expKey2);

    const impKey1 = await subtle.importKey('raw', expKey1, name, true,
                                           ['encrypt', 'decrypt']);
    const impKey2 = await subtle.importKey('raw', expKey2, name, true,
                                           ['encrypt', 'decrypt']);
    const impKey3 = await subtle.importKey('raw', expKey3, name, true,
                                           ['encrypt', 'decrypt']);

    assert.deepEqual(await subtle.exportKey('raw', impKey1), expKey1);
    assert.deepEqual(await subtle.exportKey('raw', impKey2), expKey2);
    assert.deepEqual(await subtle.exportKey('raw', impKey3), expKey3);
  };
}

describe('AES-CTR', () => {
  it('should generate, import and export keys',
     testGenImportExport('AES-CTR'));

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
    assert.deepEqual(ciphertext,
                     Buffer.from('0bdbe0f2de637f43b9d86f8bb0ba5f05', 'hex'));

    const deciphered = await subtle.decrypt({
      name: 'AES-CTR',
      counter,
      length
    }, key, ciphertext);
    assert.deepEqual(deciphered, plaintext);
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
    assert.deepEqual(encryptedFirstHalf, encryptedSecondHalf);

    let decrypted = await subtle.decrypt({ name: 'AES-CTR', counter, length },
                                         key, ciphertext);
    assert.deepEqual(decrypted, plaintext);

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
    assert.deepEqual(ciphertext.slice(blockSize, 2 * blockSize),
                     expectedSecondBlock);

    decrypted = await subtle.decrypt({ name: 'AES-CTR', counter, length }, key,
                                     ciphertext);
    assert.deepEqual(decrypted, plaintext);
  });
});

describe('AES-CBC', () => {
  it('should generate, import and export keys',
     testGenImportExport('AES-CBC'));

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
    assert.deepEqual(ciphertext,
                     Buffer.from('8bb6173879b0f7a8899397e0fde3a3c88c69e86b18' +
                                 'eb74f8629be60287c89552', 'hex'));

    const deciphered = await subtle.decrypt({
      name: 'AES-CBC',
      iv
    }, key, ciphertext);
    assert.deepEqual(deciphered, plaintext);
  });
});

describe('AES-GCM', () => {
  it('should generate, import and export keys',
     testGenImportExport('AES-GCM'));

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
    assert.deepEqual(ciphertext,
                     Buffer.from('7080337fe4a1f8d8d96fa061ccfdb8cda6dacbf3f2' +
                                 '7ef1dc85190feddc4befdd', 'hex'));

    const deciphered = await subtle.decrypt({
      name: 'AES-GCM',
      iv
    }, key, ciphertext);
    assert.deepEqual(deciphered, plaintext);
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
    assert.deepEqual(ciphertext,
                     Buffer.from('7080337fe4a1f8d8d96fa061ccfdb8cda6dacbf3f2' +
                                 '7ef1dc85190feddc4b', 'hex'));

    const deciphered = await subtle.decrypt({
      name: 'AES-GCM',
      iv,
      tagLength: 112
    }, key, ciphertext);
    assert.deepEqual(deciphered, plaintext);
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
    assert.deepEqual(ciphertext,
                     Buffer.from('2f136ce56f36acf081476d227c0fb89ed4e0fcd07b' +
                                 '3b8de9d412f99a2c2d', 'hex'));

    const deciphered = await subtle.decrypt({
      name: 'AES-GCM',
      iv,
      tagLength: 112
    }, key, ciphertext);
    assert.deepEqual(deciphered, plaintext);
  });
});

describe('AES-KW', () => {
  it('should generate, import and export keys',
     testGenImportExport('AES-KW'));

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
    assert.deepEqual(await subtle.exportKey('raw', unwrappedKey),
                     await subtle.exportKey('raw', keyToWrap));
  });
});
