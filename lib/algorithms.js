'use strict';

const { AES_CTR, AES_CBC, AES_GCM, AES_KW } = require('./algorithms/aes');
const { HKDF } = require('./algorithms/hkdf');
const { PBKDF2 } = require('./algorithms/pbkdf2');
const { SHA_1, SHA_256, SHA_384, SHA_512 } = require('./algorithms/sha');
const { NotSupportedError } = require('./errors');

const algorithms = [
  AES_CTR,
  AES_CBC,
  AES_GCM,
  AES_KW,

  HKDF,

  PBKDF2,

  SHA_1,
  SHA_256,
  SHA_384,
  SHA_512
];

function objectFromArray(array, fn) {
  const obj = {};
  for (const val of array)
    fn(obj, val);
  return obj;
}

const supportedAlgorithms = objectFromArray([
  // This corresponds to section 18.2.2 of the WebCrypto spec.
  'encrypt',
  'decrypt',
  'sign',
  'verify',
  'deriveBits',
  'wrapKey',
  'unwrapKey',
  'digest',
  'generateKey',
  'importKey',
  'exportKey',
  'get key length',

  // The following APIs are for internal use only.
  'get hash function'
], (opsByName, op) => {
  opsByName[op] = objectFromArray(algorithms, (algsByName, alg) => {
    if (typeof alg[op] === 'function')
      algsByName[alg.name.toLowerCase()] = alg;
  });
});

function getAlgorithm(alg, op) {
  if (typeof alg !== 'string') {
    if (typeof alg !== 'object')
      throw new SyntaxError();
    const { name } = alg;
    if (typeof name !== 'string')
      throw new SyntaxError();
    return getAlgorithm(alg.name, op);
  }

  const impl = supportedAlgorithms[op][alg.toLowerCase()];
  if (impl === undefined)
    throw new NotSupportedError();
  return impl;
}

module.exports.getAlgorithm = getAlgorithm;
