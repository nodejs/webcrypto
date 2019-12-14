'use strict';

const algorithms = require('./algorithms');
const { DataError } = require('./errors');

function callOp(op) {
  return (algorithm) => algorithms.getAlgorithm(algorithm, op)[op]();
}

module.exports.opensslHashFunctionName = callOp('get hash function');
module.exports.getHashBlockSize = callOp('get hash block size');

module.exports.limitUsages = (usages, allowed, err = SyntaxError) => {
  for (const usage of usages) {
    if (!allowed.includes(usage))
      throw new err();
  }
};

// Variant of base64 encoding as described in
// https://tools.ietf.org/html/rfc4648#section-5
module.exports.decodeBase64Url = (enc) => {
  if (typeof enc !== 'string')
    throw new DataError();

  enc = enc.split('').map((c) => {
    switch (c) {
      case '-':
        return '+';
      case '_':
        return '/';
      default:
        return c;
    }
  }).join('');

  return Buffer.from(enc, 'base64');
};

module.exports.encodeBase64Url = (enc) => {
  return enc.toString('base64').split('').map((c) => {
    switch (c) {
      case '+':
        return '-';
      case '/':
        return '_';
      case '=':
        return '';
      default:
        return c;
    }
  }).join('');
};
