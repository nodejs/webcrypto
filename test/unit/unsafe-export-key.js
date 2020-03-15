'use strict';

const assert = require('assert');

const { crypto: { subtle }, unsafeExportKey } = require('../../');

describe('unsafeExportKey', () => {
  it('should allow exporting non-extractable keys', async () => {
    const originalKey = await subtle.generateKey(
      {
        name: 'AES-CBC',
        length: 256
      },
      false,
      ['encrypt']
    );

    assert.rejects(() => {
      return subtle.exportKey('jwk', originalKey);
    }, {
      name: 'InvalidAccessError'
    });

    const iv = Buffer.alloc(16);
    const plaintext = Buffer.from('Hello world');
    const ciphertext = await subtle.encrypt({ name: 'AES-CBC', iv },
                                            originalKey,
                                            plaintext);

    const exportedKey = await unsafeExportKey('jwk', originalKey);
    const restoredKey = await subtle.importKey('jwk',
                                               exportedKey,
                                               originalKey.algorithm,
                                               exportedKey.ext,
                                               exportedKey.key_ops);

    assert.strictEqual(restoredKey.algorithm.name, 'AES-CBC');
    assert.strictEqual(restoredKey.algorithm.length, 256);
    assert.strictEqual(restoredKey.extractable, false);
    assert.deepStrictEqual(restoredKey.usages, ['encrypt']);

    const newCiphertext = await subtle.encrypt({ name: 'AES-CBC', iv },
                                               restoredKey,
                                               plaintext);
    assert.deepStrictEqual(newCiphertext, ciphertext);
  });
});
