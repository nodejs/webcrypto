'use strict';

const assert = require('assert');

const { subtle } = require('../../../');

describe('SHA', () => {

  it('should support SHA-1', async () => {
    const data = Buffer.from('Hello world', 'utf8');
    const digest = await subtle.digest('SHA-1', data);
    assert(Buffer.isBuffer(digest));
    assert.strictEqual(digest.toString('hex'),
                       '7b502c3a1f48c8609ae212cdfb639dee39673f5e');
  });

  it('should support SHA-256', async () => {
    const data = Buffer.from('Hello world', 'utf8');
    const digest = await subtle.digest('SHA-256', data);
    assert(Buffer.isBuffer(digest));
    assert.strictEqual(digest.toString('hex'),
                       '64ec88ca00b268e5ba1a35678a1b5316' +
                       'd212f4f366b2477232534a8aeca37f3c');
  });

  it('should support SHA-384', async () => {
    const data = Buffer.from('Hello world', 'utf8');
    const digest = await subtle.digest('SHA-384', data);
    assert(Buffer.isBuffer(digest));
    assert.strictEqual(digest.toString('hex'),
                       '9203b0c4439fd1e6ae5878866337b7c5' +
                       '32acd6d9260150c80318e8ab8c27ce33' +
                       '0189f8df94fb890df1d298ff360627e1');
  });

  it('should support SHA-512', async () => {
    const data = Buffer.from('Hello world', 'utf8');
    const digest = await subtle.digest('SHA-512', data);
    assert(Buffer.isBuffer(digest));
    assert.strictEqual(digest.toString('hex'),
                       'b7f783baed8297f0db917462184ff4f0' +
                       '8e69c2d5e5f79a942600f9725f58ce1f' +
                       '29c18139bf80b06c0fff2bdd34738452' +
                       'ecf40c488c22a7e3d80cdf6f9c1c0d47');
  });

});
