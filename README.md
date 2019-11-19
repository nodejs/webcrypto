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

A coverage report can be generated using the command `npm run coverage`.

A subset of web-platform-tests can also be used for testing. The `test/wpt/wpt`
submodule must be initialized in order to use them. You can run the WPTs
using `npm run wpt`. Proposed changes do not need to pass all WPTs, but they
should not break tests that passed without the changes.

### Linting

This repository uses ESLint. Use `npm run lint` to check the code.

[WebCrypto specification]: https://www.w3.org/TR/WebCryptoAPI/
