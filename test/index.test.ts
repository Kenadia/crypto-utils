import test from 'ava'

import * as cryptoUtils from '../src/index'

test.before(async () => cryptoUtils.ready)

test('x25519GenKey', t => {
  const { publicKey, privateKey } = cryptoUtils.x25519GenKey()
  t.is(publicKey.length, 32)
  t.is(privateKey.length, 32)
})

test('x25519Encrypt', t => {
  const plaintext = Buffer.from('message')
  const aad = Buffer.from('616164', 'hex')
  const nonce = Buffer.from('000000000102030405060708', 'hex')
  const publicKey = Buffer.from('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex')
  const privateKey = Buffer.from('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', 'hex')
  const encryptionResult = cryptoUtils.x25519Encrypt(plaintext, nonce, aad, privateKey, publicKey)
  t.deepEqual(encryptionResult, {
    ciphertext: Buffer.from('662d51123e7e88', 'hex'),
    mac: Buffer.from('1583fa946ef1abb684c6fa1a1c81fc26', 'hex'),
    nonce: Buffer.from('000000000102030405060708', 'hex'),
    aad: Buffer.from('616164', 'hex'),
  })
})

test('x25519Decrypt', t => {
  const publicKey = Buffer.from('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex')
  const privateKey = Buffer.from('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', 'hex')
  const encryptionResult = {
    ciphertext: Buffer.from('662d51123e7e88', 'hex'),
    mac: Buffer.from('1583fa946ef1abb684c6fa1a1c81fc26', 'hex'),
    nonce: Buffer.from('000000000102030405060708', 'hex'),
    aad: Buffer.from('616164', 'hex'),
  }
  const decrypted = cryptoUtils.x25519Decrypt(encryptionResult, privateKey, publicKey)
  t.deepEqual(decrypted, Buffer.from('message'))
})

test('x25519Encrypt works with no AAD', t => {
  const plaintext = Buffer.from('message')
  const publicKey = Buffer.from('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex')
  const privateKey = Buffer.from('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', 'hex')
  const nonce = Buffer.from('000000000102030405060708', 'hex')
  const encryptionResult = cryptoUtils.x25519Encrypt(plaintext, nonce, null, privateKey, publicKey)
  const decrypted = cryptoUtils.x25519Decrypt(encryptionResult, privateKey, publicKey)

  t.deepEqual(encryptionResult, {
    ciphertext: Buffer.from('662d51123e7e88', 'hex'),
    mac: Buffer.from('75acb4f1ec2246320a66cadb48637058', 'hex'),
    nonce: Buffer.from('000000000102030405060708', 'hex'),
    aad: null,
  })
  t.deepEqual(decrypted, plaintext)
})

test('x25519Encrypt defaults nonce to random if not provided', t => {
  const plaintext = Buffer.from('message')
  const publicKey = Buffer.from('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex')
  const privateKey = Buffer.from('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', 'hex')
  const encryptionResult = cryptoUtils.x25519Encrypt(plaintext, null, null, privateKey, publicKey)
  const decrypted = cryptoUtils.x25519Decrypt(encryptionResult, privateKey, publicKey)
  t.is(encryptionResult.aad, null)
  t.is(encryptionResult.nonce.length, 12)
  t.deepEqual(decrypted, plaintext)
})

test('encrypt/decrypt round trip with sender and recipient key pairs', t => {
  const sender = cryptoUtils.x25519GenKey()
  const recipient = cryptoUtils.x25519GenKey()
  const plaintext = Buffer.from('message')
  const encrypted = cryptoUtils.x25519Encrypt(plaintext, null, null, sender.privateKey, recipient.publicKey)
  const decrypted = cryptoUtils.x25519Decrypt(encrypted, recipient.privateKey, sender.publicKey)
  t.deepEqual(decrypted, plaintext)
})

test('encodeBase64UrlUnpadded', t => {
  const testBuffer = Buffer.from('lfcQI+u/gpCYyDm5z14zwg==', 'base64')
  const res = cryptoUtils.encodeBase64UrlUnpadded(testBuffer)
  t.deepEqual(res, 'lfcQI-u_gpCYyDm5z14zwg')
})

test('blake2b', t => {
  const testBuffer = Buffer.from('abc')
  const res = cryptoUtils.blake2b(testBuffer)
  t.deepEqual(res.toString('base64'), 'vd2BPGNCOXIxce8/7phXm5SWTjuxyz5CcmLIwGjVIxk=')
})
