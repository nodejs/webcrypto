import { getRandomValues } from './random.js';
export { getRandomValues } from './random.js';

import subtle_ from './subtle.js';
export const subtle = subtle_;

// Spec: https://www.w3.org/TR/WebCryptoAPI/#crypto-interface
export default {
  subtle,
  getRandomValues
};
