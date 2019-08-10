# WebCrypto Prototype for Node.js

This is a partial and experimental WebCrypto implementation for the Node.js
platform.

## Asynchonicity

The WebCrypto specification requires almost all operations to be completed
asynchronously, however, Node.js implements very few operations asynchronously.
Usually, this is not a problem, since most cryptographic functions are
incredibly fast compared to the overhead that comes with asynchronicity,
and because Node.js implements most cryptographic features through efficient
streaming interfaces. WebCrypto has no streaming interfaces but only one-shot
APIs. Encrypting, hashing, signing or verifying large amounts of data is thus
difficult in WebCrypto without underlying asynchronous APIs.

## Development

### Structure

The main export of this package is implemented in `lib/index.js` and represents
the `Crypto` interface as defined in section 10 of the
[WebCrypto specification][]. It contains two members:

- The `subtle` attribute is implemented in `lib/subtle.js`, including all
  methods described in section 14.3 of the WebCrypto specification. These
  methods usually delegate work to one or more cryptographic operations
  that are listed in section 18.2.2 and implemented in `lib/algorithms/`.
- The `getRandomValues` function is implemented in `lib/random.js`.

### Tests

The `test` directory contains a small number of unit tests. All of these tests
are required to pass after each commit. You can run unit tests using `npm test`.

It is our intention to add Web Platform Tests (WPT) at some point. When this
happens, not all WPTs are required to pass, but if a test passes, it must not be
broken by a later commit.

### Linting

This repository uses ESLint. Use `npm run lint` to check the code.

[WebCrypto specification]: https://www.w3.org/TR/WebCryptoAPI/
