/**
 * Unencrypted MTProto handshake primitives.
 *
 * A fresh auth key is required for every data center. This module owns the
 * plaintext wire format for every step of the auth-key exchange; the expensive
 * RSA/DH arithmetic lives in handshake.ts and runs only in Node (see
 * scripts/gen-dc-sessions.ts) so a Worker never pays its CPU cost.
 *
 * References: core.telegram.org/mtproto/auth_key and samples-auth_key.
 */

import { TlWriter, TlReader, IDs } from "./tl"

export const DH_CONST = {
  reqPqMulti: 0xbe7e8ef1,
  resPq: 0x05162463,
  pQInnerDataDc: 0xa9f55f95,
  reqDhParams: 0xd712e4be,
  serverDhParamsOk: 0xd0e8075c,
  serverDhInnerData: 0xb5890dba,
  clientDhInnerData: 0x6643b654,
  setClientDhParams: 0xf5045f1f,
  dhGenOk: 0x3bcbf734,
  dhGenRetry: 0x3bb3bd94,
  dhGenFail: 0x2dac4f1b,
} as const

export interface ResPq {
  nonce: Uint8Array
  serverNonce: Uint8Array
  pq: bigint
  fingerprints: bigint[]
}

/** Builds the plaintext req_pq_multi envelope (auth_key_id = 0). */
export function reqPqEnvelope(nonce: Uint8Array, messageId: bigint): Uint8Array {
  if (nonce.length !== 16) throw new Error("reqly: nonce must be 16 bytes")
  const body = new TlWriter().uint(DH_CONST.reqPqMulti)
  const bytes = body.result()
  const payload = new Uint8Array(24 + bytes.length + nonce.length)
  const view = new DataView(payload.buffer)
  view.setBigInt64(0, 0n, true)
  view.setBigInt64(8, messageId, true)
  view.setInt32(16, bytes.length + nonce.length, true)
  payload.set(bytes, 20)
  payload.set(nonce, 24)
  return payload
}

function readBigIntBE(bytes: Uint8Array): bigint {
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  return value
}

/** Parses a plaintext resPQ reply, skipping the 20-byte envelope. */
export function parseResPq(frame: Uint8Array): ResPq {
  if (frame.length < 20) throw new Error("reqly: resPQ frame too short")
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength)
  if (view.getBigInt64(0, true) !== 0n) throw new Error("reqly: resPQ is not plaintext")
  const body = frame.slice(20)
  const reader = new TlReader(body)
  if (reader.uint() !== DH_CONST.resPq) throw new Error("reqly: unexpected resPQ constructor")
  const nonce = reader.raw(16)
  const serverNonce = reader.raw(16)
  const pqBytes = reader.bytes()
  if (reader.uint() !== IDs.vector) throw new Error("reqly: resPQ fingerprint vector missing")
  const count = reader.uint()
  const fingerprints: bigint[] = []
  for (let index = 0; index < count; index += 1) fingerprints.push(reader.long())
  return { nonce, serverNonce, pq: readBigIntBE(pqBytes), fingerprints }
}

/** Miller-Rabin with deterministic bases for 64-bit pq factorization. */
function isPrime(value: bigint): boolean {
  if (value < 2n) return false
  for (const prime of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (value === prime) return true
    if (value % prime === 0n) return false
  }
  let d = value - 1n
  let shifts = 0
  while (d % 2n === 0n) {
    d /= 2n
    shifts += 1
  }
  const bases = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]
  for (const base of bases) {
    let x = modPow(base, d, value)
    if (x === 1n || x === value - 1n) continue
    let witness = false
    for (let index = 1; index < shifts; index += 1) {
      x = (x * x) % value
      if (x === value - 1n) {
        witness = true
        break
      }
    }
    if (!witness) return false
  }
  return true
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
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

function pollardRho(value: bigint): bigint {
  if (value % 2n === 0n) return 2n
  let x = 2n
  let y = 2n
  let factor = 1n
  while (factor === 1n) {
    x = (x * x + 1n) % value
    y = (y * y + 1n) % value
    y = (y * y + 1n) % value
    factor = gcd(x > y ? x - y : y - x, value)
  }
  return factor
}

function gcd(left: bigint, right: bigint): bigint {
  let a = left
  let b = right
  while (b !== 0n) {
    const next = a % b
    a = b
    b = next
  }
  return a
}

/** Splits pq into two prime cofactors p < q. */
export function factorPq(pq: bigint): { p: bigint; q: bigint } {
  if (pq < 4n) throw new Error("reqly: pq too small")
  let factor = pollardRho(pq)
  if (factor === pq || !isPrime(factor)) {
    const root = BigInt(Math.floor(Math.sqrt(Number(pq))))
    factor = 2n
    for (let candidate = root; candidate > 1n; candidate -= 1n) {
      if (pq % candidate === 0n && isPrime(candidate)) {
        factor = candidate
        break
      }
    }
  }
  const p = factor < pq / factor ? factor : pq / factor
  const q = pq / p
  if (!isPrime(p) || !isPrime(q)) throw new Error("reqly: pq factorization failed")
  return { p, q }
}

/** Big-endian byte representation of a non-negative integer. */
export function bigIntBytes(value: bigint): Uint8Array {
  if (value === 0n) return new Uint8Array(0)
  let hex = value.toString(16)
  if (hex.length % 2) hex = `0${hex}`
  const out = new Uint8Array(hex.length / 2)
  for (let index = 0; index < out.length; index += 1) out[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  return out
}

/** Wraps a TL body in the plaintext (auth_key_id = 0) MTProto envelope. */
export function plainEnvelope(body: Uint8Array, messageId: bigint): Uint8Array {
  const frame = new Uint8Array(20 + body.length)
  const view = new DataView(frame.buffer)
  view.setBigInt64(0, 0n, true)
  view.setBigInt64(8, messageId, true)
  view.setInt32(16, body.length, true)
  frame.set(body, 20)
  return frame
}

/** p_q_inner_data_dc — the proof-of-work payload encrypted with RSA_PAD. */
export function pqInnerDataDc(
  pq: Uint8Array,
  p: Uint8Array,
  q: Uint8Array,
  nonce: Uint8Array,
  serverNonce: Uint8Array,
  newNonce: Uint8Array,
  dcId: number,
): Uint8Array {
  return new TlWriter()
    .uint(DH_CONST.pQInnerDataDc)
    .bytes(pq)
    .bytes(p)
    .bytes(q)
    .raw(nonce)
    .raw(serverNonce)
    .raw(newNonce)
    .int(dcId)
    .result()
}

/** req_DH_params plaintext envelope. */
export function reqDhParamsEnvelope(
  nonce: Uint8Array,
  serverNonce: Uint8Array,
  p: Uint8Array,
  q: Uint8Array,
  fingerprint: bigint,
  encryptedData: Uint8Array,
  messageId: bigint,
): Uint8Array {
  const body = new TlWriter()
    .uint(DH_CONST.reqDhParams)
    .raw(nonce)
    .raw(serverNonce)
    .bytes(p)
    .bytes(q)
    .long(fingerprint)
    .bytes(encryptedData)
    .result()
  return plainEnvelope(body, messageId)
}

export interface ServerDhParamsOk {
  nonce: Uint8Array
  serverNonce: Uint8Array
  encryptedAnswer: Uint8Array
}

/** Parses a server_DH_params_ok plaintext reply (20-byte envelope included). */
export function parseServerDhParamsOk(frame: Uint8Array): ServerDhParamsOk {
  if (frame.length < 20) throw new Error("reqly: server_DH_params_ok frame too short")
  const reader = new TlReader(frame.slice(20))
  const constructor = reader.uint()
  if (constructor !== DH_CONST.serverDhParamsOk) {
    throw new Error(`reqly: unexpected server DH params 0x${constructor.toString(16)}`)
  }
  return { nonce: reader.raw(16), serverNonce: reader.raw(16), encryptedAnswer: reader.bytes() }
}

export interface ServerDhInnerData {
  nonce: Uint8Array
  serverNonce: Uint8Array
  g: number
  prime: bigint
  gA: bigint
  serverTime: number
}

/** Parses the decrypted server_DH_inner_data payload. */
export function parseServerDhInnerData(answer: Uint8Array): ServerDhInnerData {
  const reader = new TlReader(answer)
  const constructor = reader.uint()
  if (constructor !== DH_CONST.serverDhInnerData) {
    throw new Error(`reqly: unexpected server DH inner data 0x${constructor.toString(16)}`)
  }
  const nonce = reader.raw(16)
  const serverNonce = reader.raw(16)
  const g = reader.uint()
  const prime = readBigIntBE(reader.bytes())
  const gA = readBigIntBE(reader.bytes())
  const serverTime = reader.uint()
  return { nonce, serverNonce, g, prime, gA, serverTime }
}

/** client_DH_inner_data — encrypted with the temporary AES key. */
export function clientDhInnerData(nonce: Uint8Array, serverNonce: Uint8Array, retryId: bigint, gB: bigint): Uint8Array {
  return new TlWriter()
    .uint(DH_CONST.clientDhInnerData)
    .raw(nonce)
    .raw(serverNonce)
    .long(retryId)
    .bytes(bigIntBytes(gB))
    .result()
}

/** set_client_DH_params plaintext envelope. */
export function setClientDhParamsEnvelope(
  nonce: Uint8Array,
  serverNonce: Uint8Array,
  encryptedData: Uint8Array,
  messageId: bigint,
): Uint8Array {
  const body = new TlWriter()
    .uint(DH_CONST.setClientDhParams)
    .raw(nonce)
    .raw(serverNonce)
    .bytes(encryptedData)
    .result()
  return plainEnvelope(body, messageId)
}

export interface DhGenOk {
  nonce: Uint8Array
  serverNonce: Uint8Array
  newNonceHash1: Uint8Array
}

/** Parses the final dh_gen_ok / dh_gen_retry / dh_gen_fail reply. */
export function parseDhGenResult(frame: Uint8Array): { kind: "ok" | "retry" | "fail"; value: DhGenOk } {
  if (frame.length < 20) throw new Error("reqly: DH result frame too short")
  const reader = new TlReader(frame.slice(20))
  const constructor = reader.uint()
  const kind = constructor === DH_CONST.dhGenOk ? "ok" : constructor === DH_CONST.dhGenRetry ? "retry" : constructor === DH_CONST.dhGenFail ? "fail" : undefined
  if (kind === undefined) throw new Error(`reqly: unexpected DH result 0x${constructor.toString(16)}`)
  return {
    kind,
    value: { nonce: reader.raw(16), serverNonce: reader.raw(16), newNonceHash1: reader.raw(16) },
  }
}
// Mellouki Jamal — Asynctric
