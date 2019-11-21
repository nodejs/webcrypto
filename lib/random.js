'use strict';

const { randomFillSync } = require('crypto');

const { QuotaExceededError, TypeMismatchError } = require('./errors');

function isIntegerTypedArray(o) {
  return o instanceof Int8Array ||
         o instanceof Uint8Array ||
         o instanceof Int16Array ||
         o instanceof Uint16Array ||
         o instanceof Int32Array ||
         o instanceof Uint32Array ||
         o instanceof Uint8ClampedArray;
}

// Spec: https://www.w3.org/TR/WebCryptoAPI/#dfn-Crypto-method-getRandomValues
module.exports.getRandomValues = (array) => {
  if (!isIntegerTypedArray(array))
    throw new TypeMismatchError();

  if (array.byteLength > 65536)
    throw new QuotaExceededError();

  randomFillSync(array);
  return array;
};
