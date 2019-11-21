import sodium from 'libsodium-wrappers'

export interface KeyPair {
  publicKey: Buffer
  privateKey: Buffer
}

export interface X25519EncryptionResult {
  ciphertext: Buffer
  mac: Buffer
  nonce: Buffer
  aad: Buffer | null
}

export const ready = sodium.ready

export function x25519GenKey(): KeyPair {
  const { publicKey, privateKey } = sodium.crypto_kx_keypair()
  return {
    publicKey: Buffer.from(publicKey),
    privateKey: Buffer.from(privateKey),
  }
}

export function x25519Encrypt(
  message: Buffer,
  nonce: Buffer | null,
  aad: Buffer | null,
  senderPrivateKey: Buffer,
  recipientPublicKey: Buffer,
): X25519EncryptionResult {
  nonce = nonce || Buffer.from(sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES))
  const dhKey = Buffer.from(sodium.crypto_scalarmult(senderPrivateKey, recipientPublicKey))
  const { ciphertext, mac } = sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(
    message,
    aad,
    null,
    nonce,
    dhKey,
  )
  sodium.memzero(dhKey)

  return {
    ciphertext: Buffer.from(ciphertext),
    mac: Buffer.from(mac),
    nonce,
    aad,
  }
}

export function x25519Decrypt(
  encryptionResult: X25519EncryptionResult,
  recipientPrivateKey: Buffer,
  senderPublicKey: Buffer,
): Buffer {
  const { ciphertext, mac, aad, nonce } = encryptionResult
  const dhKey = Buffer.from(sodium.crypto_scalarmult(recipientPrivateKey, senderPublicKey))
  const decrypted: Uint8Array = sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(
    null,
    ciphertext,
    mac,
    aad,
    nonce,
    dhKey,
  )
  sodium.memzero(dhKey)
  return Buffer.from(decrypted)
}

export function decodeBase64UrlUnpadded(s: string): Buffer {
  return Buffer.from(s, 'base64')
}

export function encodeBase64UrlUnpadded(bytes: Buffer): string {
  return bytes
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

export function blake2b(input: Buffer): Buffer {
  return Buffer.from(sodium.crypto_generichash(32, new Uint8Array(input)))
}
