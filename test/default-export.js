'use strict';

const assert = require('assert');

const crypto = require('../');

describe('Default export', () => {
  it('should have getRandomBytes', () => {
    assert.strictEqual(typeof crypto.getRandomValues, 'function');
  });

  it('should have subtle', () => {
    assert.strictEqual(typeof crypto.subtle, 'object');
  });

  it('should not have any other properties', () => {
    assert.strictEqual(Object.keys(crypto).length, 2);
  });
});
