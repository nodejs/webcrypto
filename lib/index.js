'use strict';

const { getRandomValues } = require('./random');
const subtle = require('./subtle');
const { CryptoKey } = require('./key');

// Spec: https://www.w3.org/TR/WebCryptoAPI/#crypto-interface
const crypto = {
  getRandomValues,
  subtle
};

module.exports = {
  crypto,
  CryptoKey
};
