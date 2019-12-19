'use strict';

const assert = require('assert');

const { crypto: { getRandomValues } } = require('../../');

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

  it('should throw if the input is invalid', () => {
    for (const notAnArrayBufferView of [undefined, null, 5, 'foo']) {
      assert.throws(() => {
        getRandomValues(notAnArrayBufferView);
      }, /TypeError/);
    }

    const buf = new ArrayBuffer(65544);
    for (const View of [Float32Array, Float64Array]) {
      assert.throws(() => {
        getRandomValues(new View(buf));
      }, /TypeMismatchError/);
    }

    assert.throws(() => {
      getRandomValues(new Uint32Array(buf));
    }, /QuotaExceededError/);
  });
});
