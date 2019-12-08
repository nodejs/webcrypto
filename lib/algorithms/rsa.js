'use strict';

const crypto = require('crypto');
const { promisify } = require('util');

const algorithms = require('../algorithms');
const {
  InvalidAccessError,
  NotSupportedError,
  OperationError
} = require('../errors');
const { kKeyMaterial, CryptoKey } = require('../key');
const { toUnsignedLongEnforceRange } = require('../idl');
const { limitUsages, opensslHashFunctionName, toBuffer } = require('../util');

const generateKeyPair = promisify(crypto.generateKeyPair);

function uint8ArrayToUint32(bigInteger) {
  let result = 0;
  for (let i = 0; i < bigInteger.length; i++) {
    if (result > 0xffffff)
      throw new NotSupportedError();
    result = (result << 8) | bigInteger[i];
  }
  return result & 0xffffffff;
}

function uint32ToUint8Array(integer) {
  const result = Buffer.alloc(8);
  let i = 7;
  while (integer !== 0) {
    result[i--] = integer & 0xff;
    integer >>= 8;
  }
  return result.slice(i + 1);
}

const rsaBase = {
  async generateKey(algorithm, extractable, usages) {
    let privateUsages, publicUsages;
    if (this.sign) {
      limitUsages(usages, ['sign', 'verify']);
      privateUsages = usages.includes('sign') ? ['sign'] : [];
      publicUsages = usages.includes('verify') ? ['verify'] : [];
    } else {
      limitUsages(usages, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);
      privateUsages = usages.filter(
        (u) => u === 'decrypt' || u === 'unwrapKey');
      publicUsages = usages.filter((u) => u === 'encrypt' || u === 'wrapKey');
    }

    const {
      hash: hashAlg,
      publicExponent: rawPublicExponent
    } = algorithm;
    const modulusLength = toUnsignedLongEnforceRange(algorithm.modulusLength);

    const hash = {
      name: algorithms.getAlgorithm(hashAlg, 'digest').name
    };

    const publicExponent = uint8ArrayToUint32(rawPublicExponent);

    const { privateKey, publicKey } = await generateKeyPair('rsa', {
      modulusLength,
      publicExponent
    });

    const alg = {
      name: this.name,
      hash,
      modulusLength,
      publicExponent: uint32ToUint8Array(publicExponent)
    };

    return {
      privateKey: new CryptoKey('private', alg, extractable, privateUsages,
                                privateKey),
      publicKey: new CryptoKey('public', alg, extractable, publicUsages,
                               publicKey)
    };
  },

  importKey(keyFormat, keyData, params, extractable, keyUsages) {
    const { hash: hashAlg } = params;

    const hash = {
      name: algorithms.getAlgorithm(hashAlg, 'digest').name
    };

    const opts = {
      key: toBuffer(keyData),
      format: 'der',
      type: keyFormat
    };

    let key;
    if (keyFormat === 'spki') {
      limitUsages(keyUsages, this.sign ? ['verify'] : ['encrypt', 'wrapKey']);
      key = crypto.createPublicKey(opts);
    } else if (keyFormat === 'pkcs8') {
      limitUsages(keyUsages, this.sign ? ['sign'] : ['decrypt', 'unwrapKey']);
      key = crypto.createPrivateKey(opts);
    } else {
      throw new NotSupportedError();
    }

    return new CryptoKey(key.type, { name: this.name, hash },
                         extractable, keyUsages, key);
  },

  exportKey(format, key) {
    if (format !== 'spki' && format !== 'pkcs8')
      throw new NotSupportedError();

    if (format === 'spki' && key.type !== 'public' ||
        format === 'pkcs8' && key.type !== 'private')
      throw new InvalidAccessError();

    return key[kKeyMaterial].export({
      format: 'der',
      type: format
    });
  }
};

// Spec: https://www.w3.org/TR/WebCryptoAPI/#rsassa-pkcs1
module.exports.RSASSA_PKCS1 = {
  name: 'RSASSA-PKCS1-v1_5',
  ...rsaBase,

  sign(algorithm, key, data) {
    const hashFn = opensslHashFunctionName(key.algorithm.hash);
    return crypto.sign(hashFn, toBuffer(data), key[kKeyMaterial]);
  },

  verify(algorithm, key, signature, data) {
    const hashFn = opensslHashFunctionName(key.algorithm.hash);
    return crypto.verify(hashFn, toBuffer(data), key[kKeyMaterial], signature);
  }
};

// Spec: https://www.w3.org/TR/WebCryptoAPI/#rsa-pss
module.exports.RSA_PSS = {
  name: 'RSA-PSS',
  ...rsaBase,

  sign(algorithm, key, data) {
    let { saltLength } = algorithm;
    saltLength = toUnsignedLongEnforceRange(saltLength);

    const hashFn = opensslHashFunctionName(key.algorithm.hash);
    return crypto.sign(hashFn, toBuffer(data), {
      key: key[kKeyMaterial],
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength
    });
  },

  verify(algorithm, key, signature, data) {
    let { saltLength } = algorithm;
    saltLength = toUnsignedLongEnforceRange(saltLength);

    const hashFn = opensslHashFunctionName(key.algorithm.hash);
    return crypto.verify(hashFn, toBuffer(data), {
      key: key[kKeyMaterial],
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength
    }, signature);
  }
};

// Spec: https://www.w3.org/TR/WebCryptoAPI/#rsa-oaep
module.exports.RSA_OAEP = {
  name: 'RSA-OAEP',
  ...rsaBase,

  encrypt(params, key, data) {
    try {
      return crypto.publicEncrypt({
        key: key[kKeyMaterial],
        oaepHash: opensslHashFunctionName(key.algorithm.hash.name),
        oaepLabel: params.label
      }, data);
    } catch {
      throw new OperationError();
    }
  },

  decrypt(params, key, data) {
    try {
      return crypto.privateDecrypt({
        key: key[kKeyMaterial],
        oaepHash: opensslHashFunctionName(key.algorithm.hash.name),
        oaepLabel: params.label
      }, data);
    } catch {
      throw new OperationError();
    }
  }
};
