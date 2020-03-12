'use strict';

const crypto = require('crypto');
const { promisify } = require('util');

const algorithms = require('../algorithms');
const {
  DataError,
  InvalidAccessError,
  NotSupportedError,
  OperationError
} = require('../errors');
const { kKeyMaterial, CryptoKey } = require('../key');
const {
  toUnsignedLongEnforceRange,
  bufferFromBufferSource
} = require('../idl');
const {
  decodeBase64Url,
  encodeBase64Url,
  limitUsages,
  opensslHashFunctionName,
  Asn1SequenceDecoder,
  Asn1SequenceEncoder
} = require('../util');

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

function jwkToDer(jwk, jwkHashMapping) {
  if (jwk.kty !== 'RSA')
    throw new DataError();

  if (jwk.use !== undefined && jwk.use !== 'sig')
    throw new DataError();

  let hash;
  if (jwk.alg !== undefined) {
    hash = jwkHashMapping[jwk.alg];
    if (hash === undefined)
      throw new DataError();
  }

  const enc = new Asn1SequenceEncoder();

  if (jwk.d === undefined) {
    enc.unsignedInteger(decodeBase64Url(jwk.n));
    enc.unsignedInteger(decodeBase64Url(jwk.e));
  } else {
    enc.unsignedInteger(Buffer.from([0]));
    enc.unsignedInteger(decodeBase64Url(jwk.n));
    enc.unsignedInteger(decodeBase64Url(jwk.e));
    enc.unsignedInteger(decodeBase64Url(jwk.d));
    enc.unsignedInteger(decodeBase64Url(jwk.p));
    enc.unsignedInteger(decodeBase64Url(jwk.q));
    enc.unsignedInteger(decodeBase64Url(jwk.dp));
    enc.unsignedInteger(decodeBase64Url(jwk.dq));
    enc.unsignedInteger(decodeBase64Url(jwk.qi));
  }

  return enc.end();
}

const kInverted = Symbol('kInverted');
function swapKeysAndValues(obj) {
  if (obj[kInverted])
    return obj[kInverted];
  const entries = Object.entries(obj).map(([k, v]) => [v, k]);
  return obj[kInverted] = Object.fromEntries(entries);
}

function derToJwk(cryptoKey, jwkHashMapping) {
  const der = cryptoKey[kKeyMaterial].export({
    format: 'der',
    type: 'pkcs1'
  });

  const dec = new Asn1SequenceDecoder(der);

  if (cryptoKey.type === 'private') {
    dec.unsignedInteger(); // TODO: Don't ignore this
  }

  const n = encodeBase64Url(dec.unsignedInteger());
  const e = encodeBase64Url(dec.unsignedInteger());
  let keyProps;

  if (cryptoKey.type === 'public') {
    keyProps = { n, e };
  } else {
    const d = encodeBase64Url(dec.unsignedInteger());
    const p = encodeBase64Url(dec.unsignedInteger());
    const q = encodeBase64Url(dec.unsignedInteger());
    const dp = encodeBase64Url(dec.unsignedInteger());
    const dq = encodeBase64Url(dec.unsignedInteger());
    const qi = encodeBase64Url(dec.unsignedInteger());
    keyProps = { n, e, d, p, q, dp, dq, qi };
  }

  dec.end();

  const alg = swapKeysAndValues(jwkHashMapping)[cryptoKey.algorithm.hash.name];

  return {
    kty: 'RSA',
    alg,
    key_ops: [...cryptoKey.usages],
    ext: cryptoKey.extractable,
    ...keyProps
  };
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

    const isPublic = keyFormat === 'spki' ||
                     (keyFormat === 'jwk' && keyData.d === undefined);

    if (isPublic)
      limitUsages(keyUsages, this.sign ? ['verify'] : ['encrypt', 'wrapKey']);
    else
      limitUsages(keyUsages, this.sign ? ['sign'] : ['decrypt', 'unwrapKey']);

    if (keyFormat === 'spki' || keyFormat === 'pkcs8') {
      keyData = bufferFromBufferSource(keyData);
    } else if (keyFormat === 'jwk') {
      keyData = jwkToDer(keyData, this.jwkHashMapping);
      keyFormat = 'pkcs1';
    } else {
      throw new NotSupportedError();
    }

    const key = (isPublic ? crypto.createPublicKey : crypto.createPrivateKey)({
      key: keyData,
      format: 'der',
      type: keyFormat
    });

    return new CryptoKey(key.type, { name: this.name, hash },
                         extractable, keyUsages, key);
  },

  exportKey(format, key) {
    if (format === 'jwk') {
      return derToJwk(key, this.jwkHashMapping);
    }

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

  jwkHashMapping: {
    RS1: 'SHA-1',
    RS256: 'SHA-256',
    RS384: 'SHA-384',
    RS512: 'SHA-512'
  },

  sign(algorithm, key, data) {
    const hashFn = opensslHashFunctionName(key.algorithm.hash);
    return crypto.sign(hashFn, bufferFromBufferSource(data), key[kKeyMaterial]);
  },

  verify(algorithm, key, signature, data) {
    const hashFn = opensslHashFunctionName(key.algorithm.hash);
    const dataBuffer = bufferFromBufferSource(data);
    return crypto.verify(hashFn, dataBuffer, key[kKeyMaterial], signature);
  }
};

// Spec: https://www.w3.org/TR/WebCryptoAPI/#rsa-pss
module.exports.RSA_PSS = {
  name: 'RSA-PSS',
  ...rsaBase,

  jwkHashMapping: {
    PS1: 'SHA-1',
    PS256: 'SHA-256',
    PS384: 'SHA-384',
    PS512: 'SHA-512'
  },

  sign(algorithm, key, data) {
    let { saltLength } = algorithm;
    saltLength = toUnsignedLongEnforceRange(saltLength);

    const hashFn = opensslHashFunctionName(key.algorithm.hash);
    return crypto.sign(hashFn, bufferFromBufferSource(data), {
      key: key[kKeyMaterial],
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength
    });
  },

  verify(algorithm, key, signature, data) {
    let { saltLength } = algorithm;
    saltLength = toUnsignedLongEnforceRange(saltLength);

    const hashFn = opensslHashFunctionName(key.algorithm.hash);
    return crypto.verify(hashFn, bufferFromBufferSource(data), {
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

  jwkHashMapping: {
    'RSA-OAEP': 'SHA-1',
    'RSA-OAEP-256': 'SHA-256',
    'RSA-OAEP-384': 'SHA-384',
    'RSA-OAEP-512': 'SHA-512'
  },

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
