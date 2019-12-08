'use strict';

function toBoolean(x) {
  return !!x;
}

function toOctetEnforceRange(x) {
  x = +x;
  if (Number.isNaN(x) || x < 0 || x > 0xff)
    throw new TypeError();
  return x >>> 0;
}

function toUnsignedLong(x) {
  return x >>> 0;
}

function toUnsignedLongEnforceRange(x) {
  x = +x;
  if (Number.isNaN(x) || x < 0 || x > 0xffffffff)
    throw new TypeError();
  return x >>> 0;
}

function toUnsignedShort(x) {
  return (x >>> 0) & 0xffff;
}

function toUnsignedShortEnforceRange(x) {
  x = +x;
  if (Number.isNaN(x) || x < 0 || x > 0xffff)
    throw new TypeError();
  return x >>> 0;
}

function requireDOMString(x) {
  if (typeof x !== 'string')
    throw new TypeError();
}

module.exports = {
  toBoolean,
  toOctetEnforceRange,
  toUnsignedLong,
  toUnsignedLongEnforceRange,
  toUnsignedShort,
  toUnsignedShortEnforceRange,

  requireDOMString
};
