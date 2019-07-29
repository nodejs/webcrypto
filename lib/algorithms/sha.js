import { createHash } from 'crypto';

function implement(name, opensslName) {
  return {
    name,

    digest(params, data) {
      return createHash(opensslName).update(data).digest();
    },

    'get hash function'() {
      return opensslName;
    }
  };
}

export const SHA_1 = implement('SHA-1', 'sha1');
export const SHA_256 = implement('SHA-256', 'sha256');
export const SHA_384 = implement('SHA-384', 'sha384');
export const SHA_512 = implement('SHA-512', 'sha512');
