'use strict';

const assert = require('assert');

const { getRandomValues } = require('../');

describe('crypto.getRandomBytes', () => {
  it('should exist', () => {
    assert.strictEqual(typeof getRandomValues, 'function');
  });

  it('should return the input parameter', () => {
    const buf = Buffer.alloc(1024);
    assert.strictEqual(getRandomValues(buf), buf);
  });

  it('should overwrite the buffer', () => {
    const zero = Buffer.alloc(1024, 0);
    const buf = getRandomValues(Buffer.alloc(1024, 0));
    assert(!buf.equals(zero));
  });

  it('should produce a different output each time', () => {
    const buf1 = getRandomValues(Buffer.alloc(1024));
    const buf2 = getRandomValues(Buffer.alloc(1024));
    assert(!buf1.equals(buf2));
  });
});
