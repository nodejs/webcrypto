'use strict';

const { getAlgorithm } = require('./algorithms');

function unsafeExportKey(format, key) {
  return getAlgorithm(key.algorithm, 'exportKey').exportKey(format, key);
}

module.exports = {
  unsafeExportKey
};
