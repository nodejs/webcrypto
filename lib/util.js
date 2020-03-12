'use strict';

const algorithms = require('./algorithms');
const { DataError } = require('./errors');

function callOp(op) {
  return (algorithm) => algorithms.getAlgorithm(algorithm, op)[op]();
}

const opensslHashFunctionName = callOp('get hash function');
const getHashBlockSize = callOp('get hash block size');

function limitUsages(usages, allowed, err = SyntaxError) {
  for (const usage of usages) {
    if (!allowed.includes(usage))
      throw new err();
  }
}

// Variant of base64 encoding as described in
// https://tools.ietf.org/html/rfc4648#section-5
function decodeBase64Url(enc) {
  if (typeof enc !== 'string')
    throw new DataError();

  enc = enc.split('').map((c) => {
    switch (c) {
      case '-':
        return '+';
      case '_':
        return '/';
      default:
        return c;
    }
  }).join('');

  return Buffer.from(enc, 'base64');
}

function encodeBase64Url(enc) {
  return enc.toString('base64').split('').map((c) => {
    switch (c) {
      case '+':
        return '-';
      case '/':
        return '_';
      case '=':
        return '';
      default:
        return c;
    }
  }).join('');
}

const tagInteger = 0x02;
const tagSequence = 0x30;

const bZero = Buffer.from([0x00]);
const bTagInteger = Buffer.from([tagInteger]);
const bTagSequence = Buffer.from([tagSequence]);

class Asn1SequenceDecoder {
  constructor(buffer) {
    if (buffer[0] !== tagSequence)
      throw new DataError();

    this.buffer = buffer;
    this.offset = 1;

    const len = this.decodeLength();
    if (len !== buffer.length - this.offset)
      throw new DataError();
  }

  decodeLength() {
    let length = this.buffer[this.offset++];
    if (length & 0x80) {
      // Long form.
      const nBytes = length & ~0x80;
      length = 0;
      for (let i = 0; i < nBytes; i++)
        length = (length << 8) | this.buffer[this.offset + i];
      this.offset += nBytes;
    }
    return length;
  }

  unsignedInteger() {
    if (this.buffer[this.offset++] !== tagInteger)
      throw new DataError();

    let length = this.decodeLength();

    // There may be exactly one leading zero (if the next byte's MSB is set).
    if (this.buffer[this.offset] === 0) {
      this.offset++;
      length--;
    }

    const result = this.buffer.slice(this.offset, this.offset + length);
    this.offset += length;
    return result;
  }

  end() {
    if (this.offset !== this.buffer.length)
      throw new DataError();
  }
}

class Asn1SequenceEncoder {
  constructor() {
    this.length = 0;
    this.elements = [];
  }

  encodeLength(len) {
    // Short form.
    if (len < 128)
      return Buffer.from([len]);

    // Long form.
    const buffer = Buffer.alloc(5);
    buffer.writeUInt32BE(len, 1);
    let offset = 1;
    while (buffer[offset] === 0)
      offset++;
    buffer[offset - 1] = 0x80 | (5 - offset);
    return buffer.slice(offset - 1);
  }

  unsignedInteger(integer) {
    // ASN.1 integers are signed, so in order to encode unsigned integers, we
    // need to make sure that the MSB is not set.
    if (integer[0] & 0x80) {
      const len = this.encodeLength(integer.length + 1);
      this.elements.push(
        bTagInteger,
        len,
        bZero,
        integer
      );
      this.length += 2 + len.length + integer.length;
    } else {
      // If the MSB is not set, enforce a minimal representation of the integer.
      let i = 0;
      while (integer[i] === 0 && (integer[i + 1] & 0x80) === 0)
        i++;

      const len = this.encodeLength(integer.length - i);
      this.elements.push(
        bTagInteger,
        this.encodeLength(integer.length - i),
        integer.slice(i)
      );
      this.length += 1 + len.length + integer.length - i;
    }
  }

  end() {
    const len = this.encodeLength(this.length);
    return Buffer.concat([bTagSequence, len, ...this.elements],
                         1 + len.length + this.length);
  }
}


module.exports = {
  opensslHashFunctionName,
  getHashBlockSize,
  limitUsages,
  decodeBase64Url,
  encodeBase64Url,
  Asn1SequenceDecoder,
  Asn1SequenceEncoder
};
