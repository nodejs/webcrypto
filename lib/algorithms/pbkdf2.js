'use strict';

const { pbkdf2 } = require('crypto');

const { OperationError, NotSupportedError } = require('../errors');
const { kKeyMaterial, CryptoKey } = require('../key');
const { limitUsages, opensslHashFunctionName } = require('../util');

module.exports.PBKDF2 = {
  name: 'PBKDF2',

  deriveBits(params, key, length) {
    const { hash, salt, iterations } = params;

    if (length === null || length % 8 !== 0)
      throw new OperationError();
    length >>= 3;

    const hashFn = opensslHashFunctionName(hash);

    if (iterations === 0)
      throw new OperationError();

    const keyDerivationKey = key[kKeyMaterial];
    return new Promise((resolve, reject) => {
      pbkdf2(keyDerivationKey, salt, iterations, length, hashFn, (err, key) => {
        if (err)
          return reject(err);
        resolve(key);
      });
    });
  },

  importKey(keyFormat, keyData, params, extractable, keyUsages) {
    if (keyFormat !== 'raw')
      throw new NotSupportedError();

    limitUsages(keyUsages, ['deriveKey', 'deriveBits']);

    if (extractable !== false)
      throw new SyntaxError();

    return new CryptoKey('secret', { name: 'PBKDF2' }, extractable, keyUsages,
                         Buffer.from(keyData));
  }
};
