import { randomFillSync } from 'crypto';
import { QuotaExceededError } from './errors.js';

// Spec: https://www.w3.org/TR/WebCryptoAPI/#dfn-Crypto-method-getRandomValues
export function getRandomValues(array) {
  if (array.byteLength > 65536)
    throw new QuotaExceededError();

  randomFillSync(array);
  return array;
}
