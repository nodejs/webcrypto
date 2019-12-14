'use strict';

const { createECDH } = require('crypto');

const { curveInfo } = require('../curves');
const {
  DataError,
  InvalidAccessError,
  OperationError,
  NotSupportedError
} = require('../errors');
const { bufferFromBufferSource, requireDOMString } = require('../idl');
const { kKeyMaterial, CryptoKey } = require('../key');
const {
  decodeBase64Url,
  encodeBase64Url,
  limitUsages
} = require('../util');

module.exports.ECDH = {
  name: 'ECDH',

  async generateKey(algorithm, extractable, usages) {
    const { namedCurve } = algorithm;
    requireDOMString(namedCurve);

    const curve = curveInfo[namedCurve];
    if (!curve)
      throw new NotSupportedError();

    limitUsages(usages, ['deriveKey', 'deriveBits']);

    const ecdh = createECDH(curve.internalName);
    const publicKey = ecdh.generateKeys();

    return {
      publicKey: new CryptoKey('public', {
        name: this.name,
        namedCurve
      }, true, [], publicKey),
      privateKey: new CryptoKey('private', {
        name: this.name,
        namedCurve
      }, extractable, usages, ecdh)
    };
  },

  importKey(keyFormat, keyData, params, extractable, keyUsages) {
    const { namedCurve } = params;
    requireDOMString(namedCurve);

    const curve = curveInfo[namedCurve];
    if (!curve)
      throw new DataError();

    let data, type;
    if (keyFormat === 'raw') {
      limitUsages(keyUsages, []);
      data = bufferFromBufferSource(keyData);
      if (data.byteLength !== 1 + 2 * curve.basePointOrderSize)
        throw new DataError();
      type = 'public';
    } else if (keyFormat === 'jwk') {
      const { d, kty, use, key_ops, ext, crv } = keyData;

      const allowedUsages = d === undefined ? [] : ['deriveKey', 'deriveBits'];
      limitUsages(keyUsages, allowedUsages);

      if (kty !== 'EC')
        throw new DataError();

      if (keyUsages.length !== 0 && use !== undefined && use !== 'enc')
        throw new DataError();

      if (key_ops !== undefined) {
        if (!Array.isArray(key_ops))
          throw new DataError();
        limitUsages(keyUsages, key_ops, DataError);
      }

      if (ext !== undefined && !ext && extractable)
        throw new DataError();

      if (crv !== namedCurve)
        throw new DataError();

      if (d === undefined) {
        const { x, y } = keyData;

        const xbuf = decodeBase64Url(x);
        const ybuf = decodeBase64Url(y);

        if (xbuf.length !== curve.basePointOrderSize ||
            ybuf.length !== curve.basePointOrderSize)
          throw new DataError();

        data = Buffer.concat([Buffer.from([0x04]), xbuf, ybuf]);
        type = 'public';
      } else {
        const { d } = keyData;

        const dbuf = decodeBase64Url(d);

        data = createECDH(curve.internalName);
        data.setPrivateKey(dbuf);
        type = 'private';
      }
    } else {
      throw new NotSupportedError();
    }

    const alg = {
      name: this.name,
      namedCurve
    };

    return new CryptoKey(type, alg, extractable, keyUsages, data);
  },

  exportKey(format, key) {
    if (format === 'raw') {
      if (key.type !== 'public')
        throw new InvalidAccessError();

      return Buffer.from(key[kKeyMaterial]);
    } else if (format === 'jwk') {
      const coordSize = curveInfo[key.algorithm.namedCurve].basePointOrderSize;
      let fields;
      if (key.type === 'public') {
        fields = {
          x: encodeBase64Url(key[kKeyMaterial].slice(1, 1 + coordSize)),
          y: encodeBase64Url(key[kKeyMaterial].slice(1 + coordSize))
        };
      } else {
        const publicKey = key[kKeyMaterial].getPublicKey();
        fields = {
          d: encodeBase64Url(key[kKeyMaterial].getPrivateKey()),
          x: encodeBase64Url(publicKey.slice(1, 1 + coordSize)),
          y: encodeBase64Url(publicKey.slice(1 + coordSize))
        };
      }

      return {
        kty: 'EC',
        crv: key.algorithm.namedCurve,
        ...fields,
        key_ops: key.usages,
        ext: key.extractable
      };
    } else {
      throw new NotSupportedError();
    }
  },

  deriveBits(params, key, length) {
    const { public: publicKey } = params;

    length >>= 3;

    const ecdh = key[kKeyMaterial];
    const secret = ecdh.computeSecret(publicKey[kKeyMaterial]);
    if (secret.length < length)
      throw new OperationError();

    return secret.slice(0, length);
  }
};
