const algorithms = [
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
