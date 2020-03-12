'use strict';

const assert = require('assert');
const { randomBytes } = require('crypto');

const {
  Asn1SequenceDecoder,
  Asn1SequenceEncoder
} = require('../../lib/util');

function throwsDataError(fn) {
  assert.throws(fn, {
    name: 'DataError'
  });
}

describe('util', () => {
  describe('Asn1SequenceDecoder', () => {
    it('should decode empty sequences', () => {
      const data = Buffer.from([0x30, 0x00]);
      const enc = new Asn1SequenceDecoder(data);
      enc.end();
    });

    it('should decode small unsigned integers', () => {
      const dec = new Asn1SequenceDecoder(Buffer.from('3005020300ffff', 'hex'));
      assert.deepStrictEqual(dec.unsignedInteger(), Buffer.from([0xff, 0xff]));
      dec.end();
    });

    it('should decode large unsigned integers', () => {
      function test(largeIntData, knownStart) {
        const buf = Buffer.concat([
          Buffer.from(knownStart, 'hex'),
          Buffer.from(largeIntData)
        ]);
        const dec = new Asn1SequenceDecoder(buf);
        const largeInt = dec.unsignedInteger();
        dec.end();
        assert.deepStrictEqual([...largeInt], largeIntData);
      }

      test([0x01, ...randomBytes(1999)], '308207d4028207d0');
      test([0xff, ...randomBytes(1998)], '308207d4028207d000');
    });

    it('should throw if ASN.1 tag is incorrect', () => {
      throwsDataError(() => {
        new Asn1SequenceDecoder(Buffer.from([0x31, 0x00]));
      });
    });

    it('should throw if the buffer is longer than the sequence', () => {
      throwsDataError(() => {
        new Asn1SequenceDecoder(Buffer.from([0x30, 0x00, 0x00]));
      });
    });

    it('should throw if the buffer is shorter than the sequence', () => {
      throwsDataError(() => {
        new Asn1SequenceDecoder(Buffer.from([0x30, 0x10, 0x00]));
      });
    });
  });

  describe('Asn1SequenceEncoder', () => {
    it('should encode empty sequences', () => {
      const enc = new Asn1SequenceEncoder();
      const buf = enc.end();
      assert.deepStrictEqual(buf, Buffer.from([0x30, 0x00]));
    });

    it('should encode small unsigned integers', () => {
      const enc = new Asn1SequenceEncoder();
      enc.unsignedInteger(Buffer.from([0xff, 0xff]));
      const buf = enc.end();
      assert.strictEqual(buf.toString('hex'), '3005020300ffff');
    });

    it('should encode large unsigned integers', () => {
      function test(largeIntData, knownStart) {
        const enc = new Asn1SequenceEncoder();
        const largeInt = Buffer.from(largeIntData);
        enc.unsignedInteger(largeInt);
        const buf = enc.end();
        assert.strictEqual(buf.length, 2008);
        const ksLength = knownStart.length >> 1;
        assert.strictEqual(buf.slice(0, ksLength).toString('hex'), knownStart);
        assert.deepStrictEqual(buf.slice(ksLength), largeInt);
      }

      test([0x01, ...randomBytes(1999)], '308207d4028207d0');
      test([0xff, ...randomBytes(1998)], '308207d4028207d000');
    });
  });
});
