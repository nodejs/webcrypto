'use strict';

const algorithms = require('./algorithms');

module.exports.toBuffer = (source) => {
  if (ArrayBuffer.isView(source)) {
    return Buffer.from(source.buffer, source.byteOffset, source.byteLength);
  } else {
    return Buffer.from(source);
  }
};

module.exports.opensslHashFunctionName = (algorithm) => {
  const op = 'get hash function';
  return algorithms.getAlgorithm(algorithm, op)[op]();
};

module.exports.limitUsages = (usages, allowed) => {
  for (const usage of usages) {
    if (!allowed.includes(usage))
      throw new SyntaxError();
  }
};
