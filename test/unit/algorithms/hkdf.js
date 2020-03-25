'use strict';

const assert = require('assert');

const { crypto: { subtle } } = require('../../../');

describe('HKDF', () => {
  it('should import keys', async () => {
    const keyBuffer = Buffer.from('passphrase', 'utf8');
    const key = await subtle.importKey('raw', keyBuffer, 'HKDF', false,
                                       ['deriveBits']);
    assert.strictEqual(key.algorithm.name, 'HKDF');
    assert.strictEqual(key.type, 'secret');
    assert.strictEqual(key.extractable, false);
    assert.deepStrictEqual(key.usages, ['deriveBits']);
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
    assert.deepStrictEqual(bits.toString('hex'),
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


  it('should pass RFC 5869 Test Cases', async () => {
    const vectors = [
      {
        hash: 'SHA-256',
        ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        salt: '000102030405060708090a0b0c',
        info: 'f0f1f2f3f4f5f6f7f8f9',
        length: 336,
        output: [
          '3cb25f25faacd57a90434f64d0362f2a',
          '2d2d0a90cf1a5a4c5db02d56ecc4c5bf',
          '34007208d5b887185865'
        ].join('')
      },
      {
        hash: 'SHA-256',
        ikm: [
          '000102030405060708090a0b0c0d0e0f',
          '101112131415161718191a1b1c1d1e1f',
          '202122232425262728292a2b2c2d2e2f',
          '303132333435363738393a3b3c3d3e3f',
          '404142434445464748494a4b4c4d4e4f'
        ].join(''),
        salt: [
          '606162636465666768696a6b6c6d6e6f',
          '707172737475767778797a7b7c7d7e7f',
          '808182838485868788898a8b8c8d8e8f',
          '909192939495969798999a9b9c9d9e9f',
          'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
        ].join(''),
        info: [
          'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf',
          'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
          'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf',
          'e0e1e2e3e4e5e6e7e8e9eaebecedeeef',
          'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
        ].join(''),
        length: 656,
        output: [
          'b11e398dc80327a1c8e7f78c596a4934',
          '4f012eda2d4efad8a050cc4c19afa97c',
          '59045a99cac7827271cb41c65e590e09',
          'da3275600c2f09b8367793a9aca3db71',
          'cc30c58179ec3e87c14c01d5c1f3434f',
          '1d87'
        ].join('')
      },
      {
        hash: 'SHA-256',
        ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        length: 336,
        output: [
          '8da4e775a563c18f715f802a063c5a31',
          'b8a11f5c5ee1879ec3454e5f3c738d2d',
          '9d201395faa4b61a96c8'
        ].join('')
      },
      {
        hash: 'SHA-1',
        ikm: '0b0b0b0b0b0b0b0b0b0b0b',
        salt: '000102030405060708090a0b0c',
        info: 'f0f1f2f3f4f5f6f7f8f9',
        length: 336,
        output: [
          '085a01ea1b10f36933068b56efa5ad81',
          'a4f14b822f5b091568a9cdd4f155fda2',
          'c22e422478d305f3f896'
        ].join('')
      },
      {
        hash: 'SHA-1',
        ikm: [
          '000102030405060708090a0b0c0d0e0f',
          '101112131415161718191a1b1c1d1e1f',
          '202122232425262728292a2b2c2d2e2f',
          '303132333435363738393a3b3c3d3e3f',
          '404142434445464748494a4b4c4d4e4f'
        ].join(''),
        salt: [
          '606162636465666768696a6b6c6d6e6f',
          '707172737475767778797a7b7c7d7e7f',
          '808182838485868788898a8b8c8d8e8f',
          '909192939495969798999a9b9c9d9e9f',
          'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
        ].join(''),
        info: [
          'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf',
          'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
          'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf',
          'e0e1e2e3e4e5e6e7e8e9eaebecedeeef',
          'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
        ].join(''),
        length: 656,
        output: [
          '0bd770a74d1160f7c9f12cd5912a06eb',
          'ff6adcae899d92191fe4305673ba2ffe',
          '8fa3f1a4e5ad79f3f334b3b202b2173c',
          '486ea37ce3d397ed034c7f9dfeb15c5e',
          '927336d0441f4c4300e2cff0d0900b52',
          'd3b4'
        ].join('')
      },
      {
        hash: 'SHA-1',
        ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        length: 336,
        output: [
          '0ac1af7002b3d761d1e55298da9d0506',
          'b9ae52057220a306e07b6b87e8df21d0',
          'ea00033de03984d34918'
        ].join('')
      },
      {
        hash: 'SHA-1',
        ikm: '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
        length: 336,
        output: [
          '2c91117204d745f3500d636a62f64f0a',
          'b3bae548aa53d423b0d1f27ebba6f5e5',
          '673a081d70cce7acfc48'
        ].join('')
      }
    ];

    for (const vector of vectors) {
      const keyBuffer = Buffer.from(vector.ikm, 'hex');
      const key = await subtle.importKey('raw', keyBuffer, 'HKDF', false,
                                         ['deriveBits']);

      const bits = await subtle.deriveBits({
        name: 'HKDF',
        hash: vector.hash,
        salt: vector.salt ? Buffer.from(vector.salt, 'hex') : Buffer.alloc(0),
        info: vector.info ? Buffer.from(vector.info, 'hex') : Buffer.alloc(0)
      }, key, vector.length);

      assert(Buffer.isBuffer(bits));
      assert.deepStrictEqual(bits.toString('hex'), vector.output);
    }
  });
});
