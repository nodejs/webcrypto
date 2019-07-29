import { createHmac } from 'crypto';

import { OperationError, NotSupportedError } from '../errors.js';
import { kKeyMaterial, CryptoKey } from '../subtle.js';
import { limitUsages, opensslHashFunctionName, toBuffer } from '../util.js';

function hmac(hash, key, data) {
  return createHmac(hash, key).update(data).digest();
}

export const HKDF = {
  name: 'HKDF',

  deriveBits(params, key, length) {
    if (length === null)
      throw new OperationError();
    length >>= 3;

    const hashFn = opensslHashFunctionName(params.hash);

    const keyDerivationKey = key[kKeyMaterial];
    const hmacKey = toBuffer(params.salt);
    const pseudoRandomKey = hmac(hashFn, hmacKey, keyDerivationKey);
    const hashLen = pseudoRandomKey.length;
    const N = Math.ceil(length / hashLen);

    const blocks = new Array(N);
    let t = Buffer.alloc(0);
    const info = toBuffer(params.info);
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
  }
};
