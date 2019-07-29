import { getAlgorithm } from './subtle.js';

export function toBuffer(source) {
  if (ArrayBuffer.isView(source)) {
    return Buffer.from(source.buffer, source.byteOffset, source.byteLength);
  } else {
    return Buffer.from(source);
  }
}

export function opensslHashFunctionName(algorithm) {
  return getAlgorithm(algorithm, 'get hash function')['get hash function']();
}

export function limitUsages(usages, allowed) {
  for (const usage of usages) {
    if (!allowed.includes(usage))
      throw new SyntaxError();
  }
}
