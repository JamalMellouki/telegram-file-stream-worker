/**
 * Complete MTProto 2.0 auth-key generation (Node-side setup only).
 *
 * This module implements the RSA_PAD and Diffie-Hellman steps that are far
 * too CPU-heavy for a Workers isolate. It runs in scripts/gen-dc-sessions.ts
 * to produce one authorized session per data center; reqly's Worker runtime
 * only ever consumes the resulting keys.
 *
 * Every function is verified against the worked example at
 * core.telegram.org/mtproto/samples-auth_key.
 */

import { sha1, igeEncrypt, igeDecrypt } from "./crypto"
import { TlWriter, TlReader } from "./tl"
import { DH_CONST } from "./dh"

const encoder = new TextEncoder()

function concat(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0)
  const output = new Uint8Array(length)
  let offset = 0
  for (const part of parts) {
    output.set(part, offset)
    offset += part.length
  }
  return output
}

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length))
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  return value
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const output = new Uint8Array(length)
  let current = value
  for (let index = length - 1; index >= 0; index -= 1) {
    output[index] = Number(current & 0xffn)
    current >>= 8n
  }
  return output
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n
  let current = base % modulus
  let power = exponent
  while (power > 0n) {
    if (power & 1n) result = (result * current) % modulus
    current = (current * current) % modulus
    power >>= 1n
  }
  return result
}

export interface RsaPublicKey {
  modulus: bigint
  exponent: bigint
  fingerprint: bigint
}

/**
 * Reads a signed 64-bit little-endian integer — how Telegram reads the low
 * 64 bits of a SHA-1 digest into a fingerprint.
 */
function readInt64LE(bytes: Uint8Array): bigint {
  let value = 0n
  for (let index = bytes.length - 1; index >= 0; index -= 1) value = (value << 8n) | BigInt(bytes[index] ?? 0)
  if (value >= 0x8000000000000000n) value -= 0x10000000000000000n
  return value
}

/** Builds a public key from the bare `rsa_public_key n e` TL representation. */
export async function rsaKeyFromBytes(nBytes: Uint8Array, eBytes: Uint8Array): Promise<RsaPublicKey> {
  // The fingerprint is SHA1 of the *TL-serialized* (length-prefixed, padded)
  // n and e, not of the bare bytes. All production keys are verified this way.
  const serialized = new TlWriter().bytes(nBytes).bytes(eBytes).result()
  const hash = await sha1(serialized)
  return { modulus: bytesToBigInt(nBytes), exponent: bytesToBigInt(eBytes), fingerprint: readInt64LE(hash.slice(-8)) }
}

/** RSA_PAD with AES-256-IGE and OAEP+-style masking, per auth_key step 4.1. */
export async function rsaPad(data: Uint8Array, key: RsaPublicKey): Promise<Uint8Array> {
  if (data.length > 144) throw new Error("reqly: data too long for RSA_PAD")
  for (;;) {
    const withPadding = concat(data, randomBytes(192 - data.length))
    const reversed = withPadding.slice().reverse()
    const tempKey = randomBytes(32)
    const dataWithHash = concat(reversed, new Uint8Array(await sha256(tempKey, withPadding)))
    const aes = igeEncrypt(dataWithHash, tempKey, new Uint8Array(32))
    const adjusted = xor(tempKey, new Uint8Array(await sha256(aes)))
    const candidate = concat(adjusted, aes)
    const value = bytesToBigInt(candidate)
    if (value >= key.modulus) continue
    const encrypted = modPow(value, key.exponent, key.modulus)
    return bigIntToBytes(encrypted, 256)
  }
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const source = concat(...parts)
  return new Uint8Array(await crypto.subtle.digest("SHA-256", source as unknown as BufferSource))
}

function xor(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length)
  for (let index = 0; index < left.length; index += 1) output[index] = left[index]! ^ right[index]!
  return output
}

/** Derives the temporary AES key/IV used by req_DH_params and set_client_DH_params. */
export async function temporaryAes(newNonce: Uint8Array, serverNonce: Uint8Array): Promise<{ key: Uint8Array; iv: Uint8Array }> {
  const a = await sha1(concat(newNonce, serverNonce))
  const b = await sha1(concat(serverNonce, newNonce))
  const c = await sha1(concat(newNonce, newNonce))
  return { key: concat(a, b.slice(0, 12)), iv: concat(b.slice(12, 20), c, newNonce.slice(0, 4)) }
}

/** Decrypts server_DH_inner_data with the temporary AES key/IV. */
export async function decryptServerDh(encrypted: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const plain = igeDecrypt(encrypted, key, iv)
  const hash = plain.slice(0, 20)
  const candidate = plain.slice(20)
  // The payload is SHA1(answer) + answer + 0..15 random padding bytes. Parse
  // the TL object to find its exact length so padding is not part of the hash.
  const reader = new TlReader(candidate)
  if (reader.uint() !== DH_CONST.serverDhInnerData) throw new Error("reqly: unexpected decrypted server DH data")
  reader.raw(16)
  reader.raw(16)
  reader.uint()
  reader.bytes()
  reader.bytes()
  reader.uint()
  const answer = candidate.slice(0, reader.position)
  if (!equalBytes(hash, new Uint8Array(await sha1(answer)))) throw new Error("reqly: server DH hash mismatch")
  return answer
}

/** Encrypts client_DH_inner_data as SHA1(data) + data + padding under the temp key. */
export async function encryptClientDh(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const hash = new Uint8Array(await sha1(data))
  const total = 16 * Math.ceil((data.length + 20) / 16)
  const padding = randomBytes(total - data.length - 20)
  return igeEncrypt(concat(hash, data, padding), key, iv)
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  let difference = 0
  for (let index = 0; index < left.length; index += 1) difference |= left[index]! ^ right[index]!
  return difference === 0
}

/** Computes the final auth_key from the server's g_a and the client secret b. */
export function computeAuthKey(gA: bigint, b: bigint, prime: bigint): Uint8Array {
  const authKey = modPow(gA, b, prime)
  const bytes = bigIntToBytes(authKey, 256)
  return bytes
}

export { modPow, concat, randomBytes, bytesToBigInt, bigIntToBytes }
