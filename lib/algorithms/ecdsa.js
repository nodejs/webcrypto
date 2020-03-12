'use strict';

const crypto = require('crypto');
const { promisify } = require('util');

const { curveInfo } = require('../curves');
const {
  DataError,
  InvalidAccessError,
  NotSupportedError
} = require('../errors');
const {
  bufferFromBufferSource,
  requireDOMString
} = require('../idl');
const { kKeyMaterial, CryptoKey } = require('../key');
const {
  limitUsages,
  opensslHashFunctionName,
  Asn1SequenceDecoder,
  Asn1SequenceEncoder
} = require('../util');

const generateKeyPair = promisify(crypto.generateKeyPair);

function convertSignatureToASN1(signature, n) {
  if (signature.length !== 2 * n)
    return undefined;

  const r = signature.slice(0, n);
  const s = signature.slice(n);

  const enc = new Asn1SequenceEncoder();
  enc.unsignedInteger(r);
  enc.unsignedInteger(s);
  return enc.end();
}

function convertSignatureFromASN1(signature, n) {
  const dec = new Asn1SequenceDecoder(signature);
  const r = dec.unsignedInteger();
  const s = dec.unsignedInteger();
  dec.end();

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
    requireDOMString(namedCurve);
    if (!curveInfo[namedCurve])
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
    requireDOMString(namedCurve);

    const opts = {
      key: bufferFromBufferSource(keyData),
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

    const dataBuffer = bufferFromBufferSource(data);
    const asn1Sig = crypto.sign(hashFn, dataBuffer, key[kKeyMaterial]);
    const n = curveInfo[key.algorithm.namedCurve].basePointOrderSize;
    return convertSignatureFromASN1(asn1Sig, n);
  },

  verify(algorithm, key, signature, data) {
    if (key.type !== 'public')
      throw new InvalidAccessError();

    const n = curveInfo[key.algorithm.namedCurve].basePointOrderSize;
    signature = convertSignatureToASN1(bufferFromBufferSource(signature), n);
    if (signature === undefined)
      return false;

    const { hash } = algorithm;
    const hashFn = opensslHashFunctionName(hash);
    return crypto.verify(hashFn, data, key[kKeyMaterial], signature);
  }
};
