import { AES_CTR, AES_CBC, AES_GCM, AES_KW } from './algorithms/aes.js';
import { HKDF } from './algorithms/hkdf.js';
import { PBKDF2 } from './algorithms/pbkdf2.js';
import { SHA_1, SHA_256, SHA_384, SHA_512 } from './algorithms/sha.js';

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

export function getAlgorithmImplementation(name, op) {
  return supportedAlgorithms[op][name.toLowerCase()];
}
