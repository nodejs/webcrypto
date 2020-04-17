'use strict';

module.exports.curveInfo = {
  'P-256': {
    internalName: 'prime256v1',
    basePointOrderSize: 32
  },
  'P-384': {
    internalName: 'secp384r1',
    basePointOrderSize: 48
  },
  'P-521': {
    internalName: 'secp521r1',
    basePointOrderSize: 66
  },
  'K-256': {
    internalName: 'secp256k1',
    basePointOrderSize: 32,
  },
};
