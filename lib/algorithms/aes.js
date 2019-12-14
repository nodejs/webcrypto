'use strict';

const {
  createCipheriv,
  createDecipheriv,
  createSecretKey,
  randomBytes: randomBytesCallback
} = require('crypto');
const { promisify } = require('util');

const { DataError, NotSupportedError, OperationError } = require('../errors');
const {
  bufferFromBufferSource,
  toOctetEnforceRange,
  toUnsignedShortEnforceRange
} = require('../idl');
const { kKeyMaterial, CryptoKey } = require('../key');
const {
  decodeBase64Url,
  encodeBase64Url,
  limitUsages
} = require('../util');

const randomBytes = promisify(randomBytesCallback);

const aesBase = {
  async generateKey(algorithm, extractable, usages) {
    limitUsages(usages, this.allowedUsages);

    const length = toUnsignedShortEnforceRange(algorithm.length);
    if (length !== 128 && length !== 192 && length !== 256)
      throw new OperationError();

    const key = createSecretKey(await randomBytes(length >> 3));
    return new CryptoKey('secret', { name: this.name, length }, extractable,
                         usages, key);
  },

  importKey(keyFormat, keyData, params, extractable, keyUsages) {
    limitUsages(keyUsages, this.allowedUsages);

    let buf;
    if (keyFormat === 'raw') {
      buf = bufferFromBufferSource(keyData);
    } else if (keyFormat === 'jwk') {
      if (typeof keyData !== 'object' || keyData === null)
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

      buf = decodeBase64Url(jwkData);

      if (jwkAlg !== undefined) {
        if (jwkAlg !== `A${buf.length << 3}${this.name.substr(4)}`)
          throw new DataError();
      }

      if (keyUsages.length !== 0 && jwkUse !== undefined && jwkUse !== 'enc')
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

    if (buf.length !== 16 && buf.length !== 24 && buf.length !== 32)
      throw new DataError();

    return new CryptoKey('secret', { name: this.name, length: buf.length << 3 },
                         extractable, keyUsages,
                         createSecretKey(buf));
  },

  exportKey(format, key) {
    const buf = key[kKeyMaterial].export();
    if (format === 'raw') {
      return buf;
    } else if (format === 'jwk') {
      return {
        kty: 'oct',
        alg: `A${buf.length << 3}${this.name.substr(4)}`,
        k: encodeBase64Url(buf),
        key_ops: key.usages,
        ext: key.extractable
      };
    } else {
      throw new NotSupportedError();
    }
  },

  'get key length'(algorithm) {
    let { length } = algorithm;
    length = toUnsignedShortEnforceRange(length);
    if (length !== 128 && length !== 192 && length !== 256)
      throw new OperationError();
    return length;
  }
};

// Spec: https://www.w3.org/TR/WebCryptoAPI/#aes-ctr
module.exports.AES_CTR = {
  name: 'AES-CTR',
  allowedUsages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  ...aesBase,

  _doCipher(iv, length, data, fn) {
    if (length === 128) {
      // Fast path for the default 128-bit length.
      return fn(data, iv);
    } else {
      // WebCrypto has a non-standard feature which allows to specify the number
      // of bits that are used as the counter. This feature is not available in
      // Node.js or OpenSSL and thus needs to be simulated: We calculate when
      // an overflow would occur that would violate the given "length" restraint
      // and restart encryption at those points with a different IV.

      let nBlocksBeforeOverflow = 1;
      for (let i = 0; i < length; i++) {
        if ((iv[15 - Math.floor(i / 8)] & (1 << (i % 8))) === 0) {
          nBlocksBeforeOverflow += 2 ** i;

          if (nBlocksBeforeOverflow >= data.length / 16)
            return fn(data, iv);
        }
      }

      const overflowIV = Buffer.from(iv);
      if (length >= 8)
        overflowIV.fill(0, 16 - Math.floor(length / 8), 16);
      overflowIV[15 - Math.floor(length / 8)] &= (0xff << (length % 8)) & 0xff;

      let result = fn(data.slice(0, nBlocksBeforeOverflow * 16), iv);
      const blocksPerCycle = 2 ** length;
      const nBlocks = Math.ceil(data.length / 16);
      for (let i = nBlocksBeforeOverflow; i < nBlocks; i += blocksPerCycle) {
        result = Buffer.concat([
          result,
          fn(data.slice(16 * i, 16 * (i + blocksPerCycle)), overflowIV)
        ]);
      }
      return result;
    }
  },

  encrypt(params, key, data) {
    const { counter } = params;
    const length = toOctetEnforceRange(params.length);

    const iv = bufferFromBufferSource(counter);
    if (iv.length !== 16)
      throw new OperationError();

    if (length === 0 || length > 128)
      throw new OperationError();

    const secretKey = key[kKeyMaterial];
    const cipher = `aes-${secretKey.symmetricKeySize << 3}-ctr`;

    return this._doCipher(iv, length, data, (data, iv) => {
      return createCipheriv(cipher, secretKey, iv).update(data);
    });
  },

  decrypt(params, key, data) {
    const { counter } = params;
    const length = toOctetEnforceRange(params.length);

    const iv = bufferFromBufferSource(counter);
    if (iv.length !== 16)
      throw new OperationError();

    if (length === 0 || length > 128)
      throw new OperationError();

    const secretKey = key[kKeyMaterial];
    const cipher = `aes-${secretKey.symmetricKeySize << 3}-ctr`;

    return this._doCipher(iv, length, data, (data, iv) => {
      return createDecipheriv(cipher, secretKey, iv).update(data);
    });
  }
};

// Spec: https://www.w3.org/TR/WebCryptoAPI/#aes-cbc
module.exports.AES_CBC = {
  name: 'AES-CBC',
  allowedUsages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  ...aesBase,

  encrypt(params, key, data) {
    let { iv } = params;

    iv = bufferFromBufferSource(iv);
    if (iv.length !== 16)
      throw new OperationError();

    const secretKey = key[kKeyMaterial];
    const cipher = `aes-${secretKey.symmetricKeySize << 3}-cbc`;

    const c = createCipheriv(cipher, secretKey, iv);
    return Buffer.concat([c.update(data), c.final()]);
  },

  decrypt(params, key, data) {
    let { iv } = params;

    iv = bufferFromBufferSource(iv);
    if (iv.length !== 16)
      throw new OperationError();

    const secretKey = key[kKeyMaterial];
    const cipher = `aes-${secretKey.symmetricKeySize << 3}-cbc`;

    const c = createDecipheriv(cipher, secretKey, iv);
    try {
      return Buffer.concat([c.update(data), c.final()]);
    } catch (err) {
      throw new OperationError(err.message);
    }
  }
};

// Spec: https://www.w3.org/TR/WebCryptoAPI/#aes-gcm
module.exports.AES_GCM = {
  name: 'AES-GCM',
  allowedUsages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  ...aesBase,

  encrypt(params, key, data) {
    const { iv, tagLength, additionalData } = params;

    const ivBuf = bufferFromBufferSource(iv);
    const secretKey = key[kKeyMaterial];
    const cipher = `aes-${secretKey.symmetricKeySize << 3}-gcm`;

    if (tagLength !== undefined && tagLength % 8 !== 0)
      throw new OperationError();

    const authTagLength = tagLength === undefined ? 16 : tagLength >> 3;
    try {
      const c = createCipheriv(cipher, secretKey, ivBuf, { authTagLength });
      if (additionalData !== undefined)
        c.setAAD(additionalData);
      return Buffer.concat([c.update(data), c.final(), c.getAuthTag()]);
    } catch (err) {
      throw new OperationError(err.message);
    }
  },

  decrypt(params, key, data) {
    const { iv, tagLength, additionalData } = params;

    const ivBuf = bufferFromBufferSource(iv);
    const secretKey = key[kKeyMaterial];
    const cipher = `aes-${secretKey.symmetricKeySize << 3}-gcm`;

    if (tagLength !== undefined && tagLength % 8 !== 0)
      throw new OperationError();

    const authTagLength = tagLength === undefined ? 16 : tagLength >> 3;
    try {
      const c = createDecipheriv(cipher, secretKey, ivBuf, { authTagLength });
      if (additionalData !== undefined)
        c.setAAD(additionalData);
      c.setAuthTag(data.slice(data.byteLength - authTagLength, data.length));
      return Buffer.concat([
        c.update(data.slice(0, data.byteLength - authTagLength)),
        c.final()
      ]);
    } catch (err) {
      throw new OperationError(err.message);
    }
  }
};

// Spec: https://www.w3.org/TR/WebCryptoAPI/#aes-kw
module.exports.AES_KW = {
  name: 'AES-KW',
  allowedUsages: ['wrapKey', 'unwrapKey'],
  ...aesBase,

  defaultIV: Buffer.from('A6A6A6A6A6A6A6A6', 'hex'),

  async wrapKey(params, key, data) {
    const secretKey = key[kKeyMaterial];
    const cipher = `aes${secretKey.symmetricKeySize << 3}-wrap`;

    const c = createCipheriv(cipher, secretKey, this.defaultIV);
    return Buffer.concat([c.update(data), c.final()]);
  },

  async unwrapKey(params, key, data) {
    const secretKey = key[kKeyMaterial];
    const cipher = `aes${secretKey.symmetricKeySize << 3}-wrap`;

    const c = createDecipheriv(cipher, secretKey, this.defaultIV);
    return Buffer.concat([c.update(data), c.final()]);
  }
};
