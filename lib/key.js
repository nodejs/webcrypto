'use strict';

const { InvalidAccessError } = require('./errors');

const kType = Symbol('kType');
const kAlgorithm = Symbol('kAlgorithm');
const kExtractable = Symbol('kExtractable');
const kUsages = Symbol('kUsages');

const kKeyMaterial = Symbol('kKeyMaterial');

// Spec: https://www.w3.org/TR/WebCryptoAPI/#cryptokey-interface
class CryptoKey {
  constructor(type, algorithm, extractable, usages, keyMaterial) {
    this[kType] = type;
    this[kAlgorithm] = algorithm;
    this[kExtractable] = extractable;
    this[kUsages] = new Set(usages);
    this[kKeyMaterial] = keyMaterial;
  }

  get type() {
    return this[kType];
  }

  get extractable() {
    return this[kExtractable];
  }

  get algorithm() {
    return this[kAlgorithm];
  }

  get usages() {
    return [...this[kUsages]];
  }
}

function requireKeyUsage(key, usage) {
  if (!key[kUsages].has(usage))
    throw new InvalidAccessError();
}

module.exports = {
  kType,
  kAlgorithm,
  kExtractable,
  kUsages,
  kKeyMaterial,
  CryptoKey,
  requireKeyUsage
};
