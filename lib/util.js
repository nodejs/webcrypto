'use strict';

const algorithms = require('./algorithms');

module.exports.toBuffer = (source) => {
  if (ArrayBuffer.isView(source)) {
    return Buffer.from(source.buffer, source.byteOffset, source.byteLength);
  } else {
    return Buffer.from(source);
  }
};

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
