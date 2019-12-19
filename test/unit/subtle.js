'use strict';

const assert = require('assert');

const { crypto: { subtle } } = require('../../');

describe('crypto.subtle', () => {
  const fns = [
    'encrypt', 'decrypt', 'sign', 'verify', 'digest',
    'generateKey', 'deriveKey', 'deriveBits',
    'importKey', 'exportKey',
    'wrapKey', 'unwrapKey'
  ];

  it('should have all SubtleCrypto functions', () => {
    for (const key of fns)
      assert.strictEqual(typeof subtle[key], 'function');
  });

  it('should not have any other properties', () => {
    assert.strictEqual(Object.keys(subtle).length, fns.length);
  });

  it('should throw if an unsupported algorithm is requested', async () => {
    return assert.rejects(subtle.digest('AES-KW', Buffer.alloc(0)),
                          /NotSupportedError/);
  });
});
