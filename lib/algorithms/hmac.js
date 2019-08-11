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
  decodeBase64Url,
  encodeBase64Url,
  limitUsages,
  opensslHashFunctionName,
  getHashBlockSize
} = require('../util');

const randomBytes = promisify(randomBytesCallback);

const hashToJwkAlgMap = {
  'SHA-1': 'HS1',
  'SHA-256': 'HS256',
  'SHA-384': 'HS384',
  'SHA-512': 'HS512'
};

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
    let { length } = params;

    limitUsages(keyUsages, ['sign', 'verify']);

    const hashAlg = {
      name: algorithms.getAlgorithm(params.hash, 'digest').name
    };

    let data;
    if (keyFormat === 'raw') {
      data = Buffer.from(keyData);
    } else if (keyFormat === 'jwk') {
      if (typeof keyData !== 'object')
        throw new DataError();

      const {
        kty: jwkKty,
        k: jwkData,
        alg: jwkAlg,
        use: jwkUse,
        key_ops: jwkKeyOps,
        ext: jwkExt
      } = keyData;

      if (jwkKty !== 'oct')
        throw new DataError();

      data = decodeBase64Url(jwkData);

      if (jwkAlg !== undefined) {
        const expectedJwkAlg = hashToJwkAlgMap[hashAlg.name];
        if (expectedJwkAlg !== undefined && expectedJwkAlg !== jwkAlg)
          throw new DataError();
      }

      if (keyUsages.length !== 0 && jwkUse !== undefined && jwkUse !== 'sig')
        throw new DataError();

      if (jwkKeyOps !== undefined) {
        if (!Array.isArray(jwkKeyOps))
          throw new DataError();
        limitUsages(keyUsages, jwkKeyOps, DataError);
      }

      if (jwkExt !== undefined && jwkExt === false && extractable) {
        throw new DataError();
      }
    } else {
      throw new NotSupportedError();
    }

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
    const bits = key[kKeyMaterial];

    if (format === 'raw') {
      return Buffer.from(bits);
    } else if (format === 'jwk') {
      const alg = hashToJwkAlgMap[key.algorithm.hash.name];
      if (alg === undefined)
        throw new NotSupportedError();

      return {
        kty: 'oct',
        k: encodeBase64Url(bits),
        alg,
        key_ops: key.usages,
        ext: key.extractable
      };
    } else {
      throw new NotSupportedError();
    }
  }
};
