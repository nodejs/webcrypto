import assert from 'assert';

import { subtle } from '../';

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
});
