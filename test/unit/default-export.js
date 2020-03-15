'use strict';

const assert = require('assert');

const defExport = require('../../');

describe('Default export', () => {
  describe('crypto property', () => {
    it('should exist', () => {
      assert.strictEqual(typeof defExport.crypto, 'object');
    });

    it('should have getRandomBytes', () => {
      assert.strictEqual(typeof defExport.crypto.getRandomValues, 'function');
    });

    it('should have subtle', () => {
      assert.strictEqual(typeof defExport.crypto.subtle, 'object');
    });

    it('should not have any other properties', () => {
      assert.strictEqual(Object.keys(defExport.crypto).length, 2);
    });
  });

  describe('CryptoKey class', () => {
    it('should exist', () => {
      assert.strictEqual(typeof defExport.CryptoKey, 'function');
    });
  });

  describe('unsafeExportKey function', () => {
    it('should exist', () => {
      assert.strictEqual(typeof defExport.unsafeExportKey, 'function');
    });
  });
});
