'use strict';

const { createHash } = require('crypto');

function implement(name, opensslName, blockSize) {
  return {
    name,

    digest(params, data) {
      return createHash(opensslName).update(data).digest();
    },

    'get hash function'() {
      return opensslName;
    },

    'get hash block size'() {
      return blockSize;
    }
  };
}

module.exports.SHA_1 = implement('SHA-1', 'sha1', 512);
module.exports.SHA_256 = implement('SHA-256', 'sha256', 512);
module.exports.SHA_384 = implement('SHA-384', 'sha384', 1024);
module.exports.SHA_512 = implement('SHA-512', 'sha512', 1024);
