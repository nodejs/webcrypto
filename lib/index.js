'use strict';

const { getRandomValues } = require('./random');
const subtle = require('./subtle');

// Spec: https://www.w3.org/TR/WebCryptoAPI/#crypto-interface
module.exports = {
  getRandomValues,
  subtle
};
