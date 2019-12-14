'use strict';

const { createHmac } = require('crypto');

const { OperationError, NotSupportedError } = require('../errors');
const { bufferFromBufferSource } = require('../idl');
const { kKeyMaterial, CryptoKey } = require('../key');
const {
  limitUsages,
  opensslHashFunctionName
} = require('../util');

function hmac(hash, key, data) {
  return createHmac(hash, key).update(data).digest();
}

module.exports.HKDF = {
  name: 'HKDF',

  deriveBits(params, key, length) {
    const hmacKey = bufferFromBufferSource(params.salt);
    const info = bufferFromBufferSource(params.info);

    if (length === 0 || length % 8 !== 0)
      throw new OperationError();
    length >>= 3;

    const hashFn = opensslHashFunctionName(params.hash);

    const keyDerivationKey = key[kKeyMaterial];
    const pseudoRandomKey = hmac(hashFn, hmacKey, keyDerivationKey);
    const hashLen = pseudoRandomKey.length;
    const N = Math.ceil(length / hashLen);

    const blocks = new Array(N);
    let t = Buffer.alloc(0);
    for (let i = 0; i < N; i++) {
      const data = Buffer.concat([t, info, Buffer.from([i + 1])],
                                 t.length + info.length + 1);
      t = blocks[i] = hmac(hashFn, pseudoRandomKey, data);
    }
    const all = Buffer.concat(blocks, N * hashLen);
    return all.slice(0, length);
  },

  importKey(keyFormat, keyData, params, extractable, keyUsages) {
    if (keyFormat !== 'raw')
      throw new NotSupportedError();

    limitUsages(keyUsages, ['deriveKey', 'deriveBits']);

    if (extractable !== false)
      throw new SyntaxError();

    return new CryptoKey('secret', { name: 'HKDF' }, extractable, keyUsages,
                         Buffer.from(keyData));
  },

  'get key length'() {
    return null;
  }
};
