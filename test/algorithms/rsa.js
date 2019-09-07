'use strict';

const assert = require('assert');
const { randomBytes } = require('crypto');

const { subtle } = require('../../');

// Disables timeouts for tests that involve key pair generation.
const NO_TIMEOUT = 0;

function testGenImportExport(name, pubKeyUsage, privKeyUsage) {
  return async () => {
    const { publicKey, privateKey } = await subtle.generateKey({
      name,
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x00, 0x00, 0x00, 0x01, 0x00, 0x01]),
      hash: 'SHA-384'
    }, true, [pubKeyUsage, privKeyUsage]);

    assert.strictEqual(publicKey.type, 'public');
    assert.strictEqual(privateKey.type, 'private');
    for (const key of [publicKey, privateKey]) {
      assert.strictEqual(key.algorithm.name, name);
      assert.strictEqual(key.algorithm.modulusLength, 2048);
      assert.deepStrictEqual(key.algorithm.publicExponent,
                             Buffer.from([0x01, 0x00, 0x01]));
      assert.strictEqual(key.algorithm.hash.name, 'SHA-384');
    }

    const expPublicKey = await subtle.exportKey('spki', publicKey);
    assert(Buffer.isBuffer(expPublicKey));
    const expPrivateKey = await subtle.exportKey('pkcs8', privateKey);
    assert(Buffer.isBuffer(expPrivateKey));

    const impPublicKey = await subtle.importKey('spki', expPublicKey, {
      name,
      hash: 'SHA-384'
    }, true, [pubKeyUsage]);
    const impPrivateKey = await subtle.importKey('pkcs8', expPrivateKey, {
      name,
      hash: 'SHA-384'
    }, true, [privKeyUsage]);

    assert.deepStrictEqual(await subtle.exportKey('spki', impPublicKey),
                           expPublicKey);
    assert.deepStrictEqual(await subtle.exportKey('pkcs8', impPrivateKey),
                           expPrivateKey);
  };
}

describe('RSASSA-PKCS1-v1_5', () => {
  it('should generate, import and export keys',
     testGenImportExport('RSASSA-PKCS1-v1_5', 'verify', 'sign'))
  .timeout(NO_TIMEOUT);

  it('should sign and verify data', async () => {
    const { privateKey, publicKey } = await subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: Buffer.from([0x01, 0x00, 0x01]),
      hash: 'SHA-256'
    }, false, ['sign', 'verify']);

    const data = randomBytes(200);
    const signature = await subtle.sign('RSASSA-PKCS1-v1_5', privateKey, data);

    const ok = await subtle.verify('RSASSA-PKCS1-v1_5', publicKey, signature,
                                   data);
    assert.strictEqual(ok, true);
  })
  .timeout(NO_TIMEOUT);

  it('should verify externally signed data', async () => {
    const publicKeyData = '30820122300d06092a864886f70d01010105000382010f0030' +
                          '82010a0282010100a09161d2ed4e0809acd3eab66d7e9f6a1e' +
                          'd6f07b1a8dc56397ddc54bf70cc1bfc0b16cbba82f5020530a' +
                          '6096d1f002deccb2f9e33db4a3492908e53fdef4782a13bbdd' +
                          '1531ff1e9ffd2f92aa4ff8191f4043c6a3ee37d961fbe718c9' +
                          'c5bf2593d1b2bec3e3be36eebedebe05fd2d26b82e3214de37' +
                          '97fec04bbf3acd983f62753b920ab2660d1efa8b46993d5c69' +
                          '3e01a40845d49a23d081790b50f96f64f1d94cd92b2e53ed6d' +
                          '98effcd9138b91b239f661d006aaa6c1b75c9831fd8e8287ed' +
                          '0ab05e02f47e9f4e2557d4f2cf94147e4a091765d38e6f9034' +
                          '71f17f49be263663cc5cc611c037b8fda6b4ef6ecdf0fb890d' +
                          'a836736ffa9e53ac8721ebf42a570203010001';
    const publicKeyBuffer = Buffer.from(publicKeyData, 'hex');
    const publicKey = await subtle.importKey('spki', publicKeyBuffer, {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256'
    }, false, ['verify']);

    const data = Buffer.from('0a0b0c0d0e0f', 'hex');
    const signatureData = '1504ce1820a7504b9cbeeca4816ef623f360b32f6f27fd8cec' +
                          'bc437e53733dc80614f14920a6300bc9b4237f679350f2dd83' +
                          '308d74711b53be2c80185453021f332d8a252fd53c41c3f45b' +
                          '142d3f775aee7bb245931b8566fd0e14891981c0a838f1cc12' +
                          '6faf123fc2f9f25226a82e78c47f230b39db185322976aaea1' +
                          'ae4bb888d5ffdc9f2e1fb0eb5e2cb717e385d9d1ba988ec9f0' +
                          '03d05338a7664c8ad62d448ca5328e247fff08816fe0a001d7' +
                          '34ce594cc8df843338a36b2228e0105485bac65f4e5a462288' +
                          '0d881f02b97799521d7589de7b365787fd9937c930991f38d6' +
                          '0d69c7f6d06fa74e2125f9ce49179f29cc3756554a38c2ac44' +
                          'b88b28aa5332';
    const signature = Buffer.from(signatureData, 'hex');

    const ok = await subtle.verify('RSASSA-PKCS1-v1_5', publicKey, signature,
                                   data);
    assert.strictEqual(ok, true);
  });
});

describe('RSA-PSS', () => {
  it('should generate, import and export keys',
     testGenImportExport('RSA-PSS', 'verify', 'sign'))
  .timeout(NO_TIMEOUT);

  it('should sign and verify data', async () => {
    const { privateKey, publicKey } = await subtle.generateKey({
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: Buffer.from([0x01, 0x00, 0x01]),
      hash: 'SHA-512'
    }, false, ['sign', 'verify']);

    const data = randomBytes(200);
    const signature = await subtle.sign({
      name: 'RSA-PSS',
      saltLength: 20
    }, privateKey, data);

    const ok = await subtle.verify({
      name: 'RSA-PSS',
      saltLength: 20
    }, publicKey, signature, data);
    assert.strictEqual(ok, true);
  })
  .timeout(NO_TIMEOUT);

  it('should verify externally signed data', async () => {
    const publicKeyData = '30820122300d06092a864886f70d01010105000382010f0030' +
                          '82010a0282010100a29c81afb9147582b01d413872c57e1e03' +
                          '33a404f1c58c1a510d24d6caf29f0edefaeb6538c4e81ebfa1' +
                          '2f131f4dd8df8dd41f1d6589f2fd7ae1ef49eacacc3c3d5b12' +
                          '1985c20157f068e3dc5b1c25e25e8d2a55a7746f6e04d3846c' +
                          '3208ce049f86fcdb7f45fa8c234d76125cbe71d3454abeaba3' +
                          '14849db26c13e6d5ccdadc203158008f49a9d65a01b180d885' +
                          '9c8315a66681a9601af0693df90706a8f3593ed95365bcbdc1' +
                          'ae37301d82e59c405f533355cb0f6998f071594c8f50155392' +
                          '40e076942fea22308fed132b6b2ea2cf20ff73ba82283488bb' +
                          '95c72082eaa099626680fccbc2ad4345ddb519a00c235e9b58' +
                          'f6bac2bb30152b6b9c88b83a39e10203010001';
    const publicKeyBuffer = Buffer.from(publicKeyData, 'hex');
    const publicKey = await subtle.importKey('spki', publicKeyBuffer, {
      name: 'RSA-PSS',
      hash: 'SHA-512'
    }, false, ['verify']);

    const data = Buffer.from('0a0b0c0d0e0f', 'hex');
    const signatureData = '3f9bdeccd358d646433ba740d8634473be4ccaac3b58961255' +
                          '84602bd1e3a84dab7c1d72e1c5c86137e714830bb618e71d08' +
                          '19422fdb6761ff742c6476aa563b284c3e1ca77ef77f482f5d' +
                          'b2f683b7efd7fcfcba0b980144852a22e5f5d70fd1473bd5f2' +
                          '0e737747a94c20c04f54a9027f385d2da7760ee95ddd94f399' +
                          '45b097aec9f3d3a2ebe0c1459a800b6fd6d4fff2b5aada9a6a' +
                          '2568044b04d13e12fde97bdbde80a6e57aa71aab39d98113b0' +
                          '4e40e150204ace1b42912586052152f28a03f11b9e0935dd2b' +
                          'f5db7745d428337eff414289e8cfdc89a61659bba4143be079' +
                          'f97b2303a0c6f23ebc6a497c5b6de813d26699bda4bdc65abf' +
                          '657c08b840a6';
    const signature = Buffer.from(signatureData, 'hex');
    const ok = await subtle.verify('RSA-PSS', publicKey, signature, data);
    assert.strictEqual(ok, true);
  });
});

describe('RSA-OAEP', () => {
  it('should generate, import and export keys',
     testGenImportExport('RSA-OAEP', 'encrypt', 'decrypt'))
  .timeout(NO_TIMEOUT);

  it('should encrypt and decrypt data', async () => {
    const hashes = [
      ['SHA-1', 20],
      ['SHA-256', 32],
      ['SHA-384', 48],
      ['SHA-512', 64]
    ];

    const modulusLength = 2048;
    const publicExponent = Buffer.from([0x01, 0x00, 0x01]);

    for (const [hash, hLen] of hashes) {
      const { privateKey, publicKey } = await subtle.generateKey({
        name: 'RSA-OAEP',
        publicExponent,
        modulusLength,
        hash
      }, false, ['encrypt', 'decrypt']);

      const maxMessageLength = (modulusLength >> 3) - 2 * (hLen + 1);
      const data = randomBytes(maxMessageLength);
      const encrypted = await subtle.encrypt('RSA-OAEP', publicKey, data);
      const decrypted = await subtle.decrypt('RSA-OAEP', privateKey, encrypted);
      assert.deepStrictEqual(decrypted, data);
    }
  })
  .timeout(NO_TIMEOUT);

  it('should decrypt externally encrypted data', async () => {
    const privKeyData = '30820276020100300d06092a864886f70d010101050004820260' +
                        '3082025c02010002818100df01caee5ec9a2811541d7b1d69b09' +
                        'b5cd2fcda3bc7ee36aec73c90f76c5e2ecacdfe4fad1c9c51390' +
                        '63d4e8b09182e3a17ff97630fcace335932d7686474ea6153dd5' +
                        'a8da0fbb868f9a9142974e0f815563f1875cb21d80275b014a9d' +
                        'ec34afa74980cb308565a982b79dcf0b74444a9633ff696f77b4' +
                        '2be335bd625816d071020301000102818018aded5c136bdb9ace' +
                        'f42e2f6d69537a05e6e22a5a682d794e0923495d92d941e980ce' +
                        'a9ae5156c8cb3c2d1a023e5c3e9e47181fab1caf7266a1aed094' +
                        'dc2bd91302d09ea329373ce8d13c6661ef473c5fe5a9918dd2d6' +
                        '53e469ae9111a8a4c43dd9a15792aa75c3a39aefead2f9b3f2cc' +
                        '34aa47ed86c1d86e1861447ee80015024100fac8b778a8bbaf3c' +
                        'b3fa0c4185bb31a664504b0aa792db9a5898c4568b737a82f062' +
                        '7a2033db6ae5e47d5d6aa46677851e6f5afbca98923b1ab780ac' +
                        '8e28a655024100e3a52dcf102e4aeb2539917c7d83d2f834fee1' +
                        '1952ebc57e89b4da3a505ffc9948a5e9fda4b1a8bb029e43c0fb' +
                        '3f49f5f82077c1b827a558324faf703d23c5ad024038113fd39e' +
                        '05b7fbde50fd04791d8cd022854101b4cd448391633622133352' +
                        '248c11b83412e3ef564e6b28c37ad5ddcac92f242c3ef3355e39' +
                        '6ee539aedeafb1024017707e92ff7b84c34985eff0fd8b814185' +
                        '5369220e63b066230fb818a106012057569e0d3bd3ff27a25161' +
                        '70916e26d368c50f0fa7428dc7d306596e191d81d1024100800c' +
                        '17d7bb714465d1098528d4da6175960e962e816bbd88cc074d04' +
                        '3aae179a9993e6374c0dab3b880b1a6bd539bfe6e5e23af83671' +
                        '791658cd347771a95ba8';
    const privateKeyBuffer = Buffer.from(privKeyData, 'hex');
    const privateKey = await subtle.importKey('pkcs8', privateKeyBuffer, {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    }, false, ['decrypt']);

    const plaintext = Buffer.from('0a0b0c0d0e0f', 'hex');
    const ciphertext = '82fc649917a95667df2335375e053edc79a48b8a4d2126dc1efa7' +
                       '703c107eacffa6826ce6eb439e680b2bde0f9a405fe259093425a' +
                       'cd153629564c95801c4cd701c4b9332b0e9a0ac0d5c5d1af24a3a' +
                       'a481e511f3f1fc6e469a3edf60af2632ad1380dd2000d896b8bb8' +
                       '088ed49debaa6b5a8d7365b9556c8ac31d5401d2e1c4';
    const decrypted = await subtle.decrypt('RSA-OAEP', privateKey,
                                           Buffer.from(ciphertext, 'hex'));
    assert.deepStrictEqual(decrypted, plaintext);
  });
});
