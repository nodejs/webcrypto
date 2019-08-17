'use strict';

const crypto = require('crypto');
const { promisify } = require('util');

const {
  DataError,
  InvalidAccessError,
  NotSupportedError,
  OperationError
} = require('../errors');
const { kKeyMaterial, CryptoKey } = require('../key');
const { limitUsages, opensslHashFunctionName, toBuffer } = require('../util');

const generateKeyPair = promisify(crypto.generateKeyPair);

const curveBasePointOrderSizes = {
  'P-256': 32,
  'P-384': 48,
  'P-521': 66
};

const byte = (b) => Buffer.from([b]);

function convertSignatureToASN1(signature, n) {
  if (signature.length !== 2 * n)
    throw new OperationError();

  const r = signature.slice(0, n);
  const s = signature.slice(n);

  function encodeLength(len) {
    // Short form.
    if (len < 128)
      return byte(len);

    // Long form.
    const buffer = Buffer.alloc(5);
    buffer.writeUInt32BE(len, 1);
    let offset = 1;
    while (buffer[offset] === 0)
      offset++;
    buffer[offset - 1] = 0x80 | (5 - offset);
    return buffer.slice(offset - 1);
  }

  function encodeUnsignedInteger(integer) {
    // ASN.1 integers are signed, so in order to encode unsigned integers, we
    // need to make sure that the MSB is not set.
    if (integer[0] & 0x80) {
      return Buffer.concat([
        byte(0x02),
        encodeLength(integer.length + 1),
        byte(0x00), integer
      ]);
    } else {
      // If the MSB is not set, enforce a minimal representation of the integer.
      let i = 0;
      while (integer[i] === 0 && (integer[i + 1] & 0x80) === 0)
        i++;
      return Buffer.concat([
        byte(0x02),
        encodeLength(integer.length - i),
        integer.slice(i)
      ]);
    }
  }

  const seq = Buffer.concat([
    encodeUnsignedInteger(r),
    encodeUnsignedInteger(s)
  ]);

  return Buffer.concat([byte(0x30), encodeLength(seq.length), seq]);
}

function convertSignatureFromASN1(signature, n) {
  let offset = 2;
  if (signature[1] & 0x80)
    offset += signature[1] & ~0x80;

  function decodeUnsignedInteger() {
    let length = signature[offset + 1];
    offset += 2;
    if (length & 0x80) {
      // Long form.
      const nBytes = length & ~0x80;
      length = 0;
      for (let i = 0; i < nBytes; i++)
        length = (length << 8) | signature[offset + 2 + i];
      offset += nBytes;
    }

    // There may be exactly one leading zero (if the next byte's MSB is set).
    if (signature[offset] === 0) {
      offset++;
      length--;
    }

    const result = signature.slice(offset, offset + length);
    offset += length;
    return result;
  }

  const r = decodeUnsignedInteger();
  const s = decodeUnsignedInteger();

  const result = Buffer.alloc(2 * n, 0);
  r.copy(result, n - r.length);
  s.copy(result, 2 * n - s.length);
  return result;
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#ecdsa
module.exports.ECDSA = {
  name: 'ECDSA',

  async generateKey(algorithm, extractable, usages) {
    limitUsages(usages, ['sign', 'verify']);
    const privateUsages = usages.includes('sign') ? ['sign'] : [];
    const publicUsages = usages.includes('verify') ? ['verify'] : [];

    const { namedCurve } = algorithm;
    if (!curveBasePointOrderSizes[namedCurve])
      throw new NotSupportedError();

    const { privateKey, publicKey } = await generateKeyPair('ec', {
      namedCurve
    });

    const alg = {
      name: this.name,
      namedCurve
    };

    return {
      privateKey: new CryptoKey('private', alg, extractable, privateUsages,
                                privateKey),
      publicKey: new CryptoKey('public', alg, extractable, publicUsages,
                               publicKey)
    };
  },

  importKey(keyFormat, keyData, params, extractable, keyUsages) {
    const { namedCurve } = params;

    const opts = {
      key: toBuffer(keyData),
      format: 'der',
      type: keyFormat
    };

    let key;
    if (keyFormat === 'spki') {
      limitUsages(keyUsages, ['verify']);
      key = crypto.createPublicKey(opts);
    } else if (keyFormat === 'pkcs8') {
      limitUsages(keyUsages, ['sign']);
      key = crypto.createPrivateKey(opts);
    } else {
      throw new NotSupportedError();
    }

    if (key.asymmetricKeyType !== 'ec')
      throw new DataError();

    return new CryptoKey(key.type, { name: this.name, namedCurve },
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
  },

  sign(algorithm, key, data) {
    if (key.type !== 'private')
      throw new InvalidAccessError();

    const { hash } = algorithm;
    const hashFn = opensslHashFunctionName(hash);

    const asn1Sig = crypto.sign(hashFn, toBuffer(data), key[kKeyMaterial]);
    const n = curveBasePointOrderSizes[key.algorithm.namedCurve];
    return convertSignatureFromASN1(asn1Sig, n);
  },

  verify(algorithm, key, signature, data) {
    if (key.type !== 'public')
      throw new InvalidAccessError();

    const n = curveBasePointOrderSizes[key.algorithm.namedCurve];
    signature = convertSignatureToASN1(toBuffer(signature), n);

    const { hash } = algorithm;
    const hashFn = opensslHashFunctionName(hash);
    return crypto.verify(hashFn, data, key[kKeyMaterial], signature);
  }
};
