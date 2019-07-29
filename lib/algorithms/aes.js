import {
  createCipheriv,
  createDecipheriv,
  createSecretKey,
  randomBytes as randomBytesCallback
} from 'crypto';
import { promisify } from 'util';

import { NotSupportedError, OperationError } from '../errors.js';
import { kKeyMaterial, CryptoKey } from '../subtle.js';
import { limitUsages, toBuffer } from '../util.js';

const randomBytes = promisify(randomBytesCallback);

const aesBase = {
  async generateKey(algorithm, extractable, usages) {
    limitUsages(usages, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);

    const { length } = algorithm;
    if (length !== 128 && length !== 192 && length !== 256)
      throw new OperationError();

    const key = createSecretKey(await randomBytes(length >> 3));
    return new CryptoKey('secret', { name: this.name, length }, extractable,
                         usages, key);
  },

  importKey(keyFormat, keyData, params, extractable, keyUsages) {
    if (keyFormat !== 'raw')
      throw new NotSupportedError();

    limitUsages(keyUsages, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);

    const buf = toBuffer(keyData);
    if (buf.length !== 16 && buf.length !== 24 && buf.length !== 32)
      throw new OperationError();

    return new CryptoKey('secret', { name: this.name, length: buf.length << 3 },
                         extractable, keyUsages,
                         createSecretKey(toBuffer(keyData)));
  },

  exportKey(format, key) {
    if (format !== 'raw')
      throw new NotSupportedError();
    return key[kKeyMaterial].export();
  },

  'get key length'(algorithm) {
    const { length } = algorithm;
    if (length !== 128 && length !== 192 && length !== 256)
      throw new OperationError();
    return length;
  }
};

// Spec: https://www.w3.org/TR/WebCryptoAPI/#aes-ctr
export const AES_CTR = {
  name: 'AES-CTR',
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
    const { counter, length } = params;

    const iv = toBuffer(counter);
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
    const { counter, length } = params;

    const iv = toBuffer(counter);
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
export const AES_CBC = {
  name: 'AES-CBC',
  ...aesBase,

  encrypt(params, key, data) {
    let { iv } = params;

    iv = toBuffer(iv);
    if (iv.length !== 16)
      throw new OperationError();

    const secretKey = key[kKeyMaterial];
    const cipher = `aes-${secretKey.symmetricKeySize << 3}-cbc`;

    const c = createCipheriv(cipher, secretKey, iv);
    return Buffer.concat([c.update(data), c.final()]);
  },

  decrypt(params, key, data) {
    let { iv } = params;

    iv = toBuffer(iv);
    if (iv.length !== 16)
      throw new OperationError();

    const secretKey = key[kKeyMaterial];
    const cipher = `aes-${secretKey.symmetricKeySize << 3}-cbc`;

    const c = createDecipheriv(cipher, secretKey, iv);
    return Buffer.concat([c.update(data), c.final()]);
  }
};

// Spec: https://www.w3.org/TR/WebCryptoAPI/#aes-gcm
export const AES_GCM = {
  name: 'AES-GCM',
  ...aesBase,

  encrypt(params, key, data) {
    const { iv, tagLength, additionalData } = params;

    const ivBuf = toBuffer(iv);
    const secretKey = key[kKeyMaterial];
    const cipher = `aes-${secretKey.symmetricKeySize << 3}-gcm`;

    const authTagLength = tagLength === undefined ? 16 : tagLength >> 3;
    const c = createCipheriv(cipher, secretKey, ivBuf, { authTagLength });
    if (additionalData !== undefined)
      c.setAAD(additionalData);
    return Buffer.concat([c.update(data), c.final(), c.getAuthTag()]);
  },

  decrypt(params, key, data) {
    const { iv, tagLength, additionalData } = params;

    const ivBuf = toBuffer(iv);
    const secretKey = key[kKeyMaterial];
    const cipher = `aes-${secretKey.symmetricKeySize << 3}-gcm`;

    const authTagLength = tagLength === undefined ? 16 : tagLength >> 3;
    const c = createDecipheriv(cipher, secretKey, ivBuf, { authTagLength });
    if (additionalData !== undefined)
      c.setAAD(additionalData);
    c.setAuthTag(data.slice(data.byteLength - authTagLength, data.length));
    return Buffer.concat([
      c.update(data.slice(0, data.byteLength - authTagLength)),
      c.final()
    ]);
  }
};

// Spec: https://www.w3.org/TR/WebCryptoAPI/#aes-kw
export const AES_KW = {
  name: 'AES-KW',
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
