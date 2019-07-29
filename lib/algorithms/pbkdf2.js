import { pbkdf2 } from 'crypto';

import { OperationError, NotSupportedError } from '../errors.js';
import { kKeyMaterial, CryptoKey } from '../subtle.js';
import { limitUsages, opensslHashFunctionName } from '../util.js';

export const PBKDF2 = {
  name: 'PBKDF2',

  deriveBits(params, key, length) {
    const { hash, salt, iterations } = params;

    if (length === null || length % 8 !== 0)
      throw new OperationError();
    length >>= 3;

    const hashFn = opensslHashFunctionName(hash);

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
