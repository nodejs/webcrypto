'use strict';

const { getAlgorithm } = require('./algorithms');
const { InvalidAccessError } = require('./errors');
const { kAlgorithm, kExtractable, requireKeyUsage } = require('./key');
const { toBuffer } = require('./util');

// Spec: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-encrypt
async function encrypt(algorithm, key, data) {
  const alg = getAlgorithm(algorithm, 'encrypt');
  if (key.algorithm.name !== alg.name)
    throw new InvalidAccessError();

  requireKeyUsage(key, 'encrypt');
  const buffer = toBuffer(data);
  return alg.encrypt(algorithm, key, buffer);
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-decrypt
async function decrypt(algorithm, key, data) {
  const alg = getAlgorithm(algorithm, 'decrypt');
  if (key.algorithm.name !== alg.name)
    throw new InvalidAccessError();

  requireKeyUsage(key, 'decrypt');
  const buffer = toBuffer(data);
  return alg.decrypt(algorithm, key, buffer);
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-sign
async function sign(algorithm, key, data) {
  const alg = getAlgorithm(algorithm, 'sign');
  if (alg.name !== key[kAlgorithm].name)
    throw new InvalidAccessError();

  requireKeyUsage(key, 'sign');
  return alg.sign(algorithm, key, data);
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-verify
async function verify(algorithm, key, signature, data) {
  const alg = getAlgorithm(algorithm, 'verify');
  if (alg.name !== key[kAlgorithm].name)
    throw new InvalidAccessError();

  requireKeyUsage(key, 'verify');
  return alg.verify(algorithm, key, signature, data);
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-digest
async function digest(algorithm, data) {
  const buffer = toBuffer(data);
  const alg = getAlgorithm(algorithm, 'digest');
  return alg.digest(algorithm, buffer);
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-generateKey
async function generateKey(algorithm, extractable, keyUsages) {
  const alg = getAlgorithm(algorithm, 'generateKey');
  return alg.generateKey(algorithm, extractable, keyUsages);
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-deriveKey
async function deriveKey(algorithm, baseKey, derivedKeyType, extractable,
                         keyUsages) {
  const alg = getAlgorithm(algorithm, 'deriveBits');
  if (alg.name !== baseKey[kAlgorithm].name)
    throw new InvalidAccessError();

  const keyAlg = getAlgorithm(derivedKeyType, 'get key length');
  const length = await keyAlg['get key length'](derivedKeyType);
  requireKeyUsage(baseKey, 'deriveKey');
  const bits = await alg.deriveBits(algorithm, baseKey, length, extractable,
                                    keyUsages);
  return keyAlg.importKey('raw', bits, derivedKeyType, extractable, keyUsages);
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-deriveBits
async function deriveBits(algorithm, key, length) {
  const alg = getAlgorithm(algorithm, 'deriveBits');
  if (alg.name !== key[kAlgorithm].name)
    throw new InvalidAccessError();

  requireKeyUsage(key, 'deriveBits');
  return alg.deriveBits(algorithm, key, length);
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-importKey
async function importKey(keyFormat, keyData, algorithm, extractable,
                         keyUsages) {
  const alg = getAlgorithm(algorithm, 'importKey');
  return alg.importKey(keyFormat, keyData, algorithm, extractable, keyUsages);
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-exportKey
async function exportKey(format, key) {
  const alg = getAlgorithm(key.algorithm, 'exportKey');
  if (!key.extractable)
    throw new InvalidAccessError();
  return alg.exportKey(format, key);
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-wrapKey
async function wrapKey(format, key, wrappingKey, wrapAlgorithm) {
  let wrapFn, alg;
  try {
    alg = getAlgorithm(wrapAlgorithm, wrapFn = 'wrapKey');
  } catch {
    alg = getAlgorithm(wrapAlgorithm, wrapFn = 'encrypt');
  }

  if (wrappingKey[kAlgorithm].name !== alg.name)
    throw new InvalidAccessError();

  requireKeyUsage(wrappingKey, 'wrapKey');

  const exportAlg = getAlgorithm(key.algorithm, 'exportKey');
  if (!key[kExtractable])
    throw new InvalidAccessError();

  let bytes = exportAlg.exportKey(format, key);
  if (format === 'jwk')
    bytes = Buffer.from(JSON.stringify(bytes), 'utf8');

  return alg[wrapFn](wrapAlgorithm, wrappingKey, bytes);
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-method-unwrapKey
async function unwrapKey(format, wrappedKey, unwrappingKey,
                         unwrapAlgorithm, unwrappedKeyAlgorithm,
                         extractable, keyUsages) {
  let unwrapFn, alg;
  try {
    alg = getAlgorithm(unwrapAlgorithm, unwrapFn = 'unwrapKey');
  } catch {
    alg = getAlgorithm(unwrapAlgorithm, unwrapFn = 'decrypt');
  }

  const importAlg = getAlgorithm(unwrappedKeyAlgorithm, 'importKey');

  if (unwrappingKey[kAlgorithm].name !== alg.name)
    throw new InvalidAccessError();

  requireKeyUsage(unwrappingKey, 'unwrapKey');

  let key = await alg[unwrapFn](unwrapAlgorithm, unwrappingKey, wrappedKey);
  if (format === 'jwk')
    key = JSON.parse(key.toString('utf8'));

  return importAlg.importKey(format, key, unwrappedKeyAlgorithm, extractable,
                             keyUsages);
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#subtlecrypto-interface
module.exports = {
  encrypt,
  decrypt,
  sign,
  verify,
  digest,

  generateKey,
  deriveKey,
  deriveBits,

  importKey,
  exportKey,

  wrapKey,
  unwrapKey
};
