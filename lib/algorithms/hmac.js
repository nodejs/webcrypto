'use strict';

const {
  createHmac,
  randomBytes: randomBytesCallback,
  timingSafeEqual
} = require('crypto');
const { promisify } = require('util');

const algorithms = require('../algorithms');
const { DataError, NotSupportedError } = require('../errors');
const { kKeyMaterial, CryptoKey } = require('../key');
const {
  limitUsages,
  opensslHashFunctionName,
  getHashBlockSize
} = require('../util');

const randomBytes = promisify(randomBytesCallback);

module.exports.HMAC = {
  name: 'HMAC',

  sign(algorithm, key, data) {
    const hashFn = opensslHashFunctionName(key.algorithm.hash);
    return createHmac(hashFn, key[kKeyMaterial]).update(data).digest();
  },

  verify(algorithm, key, signature, data) {
    return timingSafeEqual(this.sign(algorithm, key, data), signature);
  },

  async generateKey(algorithm, extractable, usages) {
    let { length } = algorithm;

    limitUsages(usages, ['sign', 'verify']);

    const hashAlg = {
      name: algorithms.getAlgorithm(algorithm.hash, 'digest').name
    };

    if (length === undefined)
      length = getHashBlockSize(hashAlg.name);
    else if (length === 0)
      throw new DataError();

    const bits = await randomBytes(length >> 3);

    return new CryptoKey('secret', {
      name: this.name,
      hash: hashAlg,
      length
    }, extractable, usages, bits);
  },

  importKey(keyFormat, keyData, params, extractable, keyUsages) {
    if (keyFormat !== 'raw')
      throw new NotSupportedError();

    let { length } = params;

    limitUsages(keyUsages, ['sign', 'verify']);

    const hashAlg = {
      name: algorithms.getAlgorithm(params.hash, 'digest').name
    };

    const data = Buffer.from(keyData);
    if (data.length === 0)
      throw new DataError();

    const dataLength = data.length << 3;
    if (length === undefined) {
      length = dataLength;
    } else if (length > dataLength || length <= dataLength - 8) {
      throw new DataError();
    }

    const alg = {
      name: this.name,
      hash: hashAlg,
      length
    };

    return new CryptoKey('secret', alg, extractable, keyUsages, data);
  },

  exportKey(format, key) {
    if (format !== 'raw')
      throw new NotSupportedError();

    const bits = key[kKeyMaterial];
    return Buffer.from(bits);
  }
};
