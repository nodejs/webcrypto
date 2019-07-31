'use strict';

const { randomFillSync } = require('crypto');

const { QuotaExceededError } = require('./errors');

// Spec: https://www.w3.org/TR/WebCryptoAPI/#dfn-Crypto-method-getRandomValues
module.exports.getRandomValues = (array) => {
  if (array.byteLength > 65536)
    throw new QuotaExceededError();

  randomFillSync(array);
  return array;
};
