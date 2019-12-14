'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const vm = require('vm');

const { crypto, CryptoKey } = require('../../');

const tests = require('./wpt-tests');

const summary = console.log;
const info = process.argv[2] === '--summary-only' ? () => {} : console.log;

function bug(message, ...info) {
  console.error(`Bail out! Fatal error: ${message}`);
  if (info.length !== 0)
    console.error(...info);
  process.exit(1);
}

process.on('unhandledRejection', (err) => bug('Unhandled rejection:', err));

let nPassedTotal = 0;
let nFailedTotal = 0;

async function runTest(test) {
  info(`# Test: ${test.name}`);

  // State management.
  const pendingTests = [];
  const queueTest = (test) => pendingTests.push(test);
  let explicitDone = test.explicitDone;
  let alreadyDone = false;
  let doneCallback;
  let addTestCallback = queueTest;

  // Statistics.
  let nPassed = 0;
  let nFailed = 0;

  // Environment for tests.
  const sandbox = {
    crypto,
    CryptoKey,
    setup(options) {
      if (arguments.length !== 1 || typeof options !== 'object')
        bug('setup() got invalid arguments:', arguments);
      assert.strictEqual(typeof options, 'object');
      if (options.explicit_done)
        explicitDone = true;
    },
    done() {
      if (arguments.length !== 0)
        bug('done() got invalid arguments:', arguments);

      if (explicitDone) {
        if (alreadyDone) {
          bug('done() was called twice.');
        } else {
          alreadyDone = true;
          if (doneCallback)
            doneCallback();
        }
      } else {
        bug('done() should not have been called.');
      }
    },
    promise_test(fn, name) {
      if (arguments.length !== 2 ||
          typeof fn !== 'function' ||
          typeof name !== 'string') {
        bug('promise_test() got invalid arguments:', arguments);
      }

      addTestCallback(['async', name, fn]);
    },
    test(fn, name) {
      if (arguments.length !== 2 ||
          typeof fn !== 'function' ||
          typeof name !== 'string') {
        bug('test() got invalid arguments:', arguments);
      }

      addTestCallback(['sync', name, fn]);
    },
    subsetTest(fn, ...args) {
      if (arguments.length <= 1 ||
          typeof fn !== 'function' ||
          typeof args[1] !== 'string') {
        bug('subsetTest() invalid arguments:', arguments);
      }

      addTestCallback(['async', args[1], () => fn(...args)]);
    },
    assert_throws(errorName, fn, name) {
      if (arguments.length !== 3 ||
          typeof errorName !== 'string' ||
          typeof fn !== 'function' ||
          typeof name !== 'string') {
        bug('assert_throws() invalid arguments:', arguments);
      }

      assert.throws(fn, (err) => {
        return err.name === errorName;
      }, name);
    },
    assert_true(value, name) {
      assert.strictEqual(value, true, name);
    },
    assert_false(value, name) {
      assert.strictEqual(value, false, name);
    },
    assert_equals(a, b, name) {
      assert.strictEqual(a, b, name);
    },
    assert_unreached(name) {
      if (arguments.length !== 1 || typeof name !== 'string')
        bug('assert_unreached() got invalid arguments:', arguments);
      assert.fail(name);
    },
    btoa(data) {
      return Buffer.from(data, 'binary').toString('base64');
    },

    Int8Array,
    Uint8Array,
    Int16Array,
    Uint16Array,
    Int32Array,
    Uint32Array,
    Uint8ClampedArray,
    Float32Array,
    Float64Array
  };

  sandbox.self = sandbox;

  async function nextTest() {
    if (pendingTests.length !== 0)
      return pendingTests.shift();

    if (!explicitDone || alreadyDone)
      return undefined;

    return new Promise((resolve, reject) => {
      doneCallback = () => {
        resolve();
        doneCallback = undefined;
        addTestCallback = queueTest;
      };
      addTestCallback = (test) => {
        resolve(test);
        doneCallback = undefined;
        addTestCallback = queueTest;
      };
    });
  }

  const context = vm.createContext(sandbox);

  for (const testFile of test.files) {
    const absPath = path.resolve(__dirname, 'wpt/WebCryptoAPI', testFile);
    const code = fs.readFileSync(absPath, { encoding: 'utf8' });

    vm.runInContext(code, context, {
      filename: absPath
    });
  }

  if (test.code) {
    vm.runInContext(test.code, context);
  }

  let singleTest;
  while ((singleTest = await nextTest()) !== undefined) {
    const [type, name, fn] = singleTest;

    try {
      type === 'sync' ? fn() : await fn();
      info(`ok - ${name}`);
      nPassed++;
    } catch (err) {
      info(`not ok - ${name}`);
      info('  ---');
      info('  stack: |-');
      info(err.stack.replace(/(^|\n)/g, '$1    '));
      info('  ...');
      nFailed++;
    }
  }

  addTestCallback = () => {
    bug('Test added after test loop ended.');
  };

  summary(`# Result for ${test.name}: ${nPassed} passed, ${nFailed} failed`);
  nPassedTotal += nPassed;
  nFailedTotal += nFailed;
}

(async () => {
  for (const test of tests) {
    await runTest(test);
  }

  summary(`# Total: ${nPassedTotal} passed, ${nFailedTotal} failed`);
})()
.catch((err) => {
  console.error(err);
  process.exit(1);
});
