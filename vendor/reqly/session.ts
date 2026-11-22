/**
 * Parsing of Telegram's version-1 StringSession format.
 *
 * The session is the only long-lived secret a reqly client needs. It carries
 * the DC address and the 2048-bit authorization key negotiated once by a
 * full client. Reusing it means an edge Worker never performs a DH exchange,
 * which is both slow and wasteful on a per-request runtime.
 */

export interface Session {
  dcId: number
  address: string
  port: number
  authKey: Uint8Array
  authKeyId: bigint
}

function requireByte(view: Uint8Array, offset: number): number {
  const value = view[offset]
  if (value === undefined) throw new Error("reqly: truncated session")
  return value
}

function readUInt16BE(view: Uint8Array, offset: number): number {
  return (requireByte(view, offset) << 8) | requireByte(view, offset + 1)
}

function readBigInt64LE(view: Uint8Array, offset: number): bigint {
  let value = 0n
  for (let index = 7; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(requireByte(view, offset + index))
  }
  return value
}

/**
 * auth_key_id is the low 64 bits of SHA-1(auth_key), read big-endian exactly
 * as Telegram's readBigIntFromBuffer(..., little=false) does.
 */
async function authKeyIdOf(authKey: Uint8Array): Promise<bigint> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", authKey as unknown as BufferSource))
  return readBigInt64LE(digest, 12)
}

export async function parseSession(encoded: string): Promise<Session> {
  if (encoded[0] !== "1") throw new Error("reqly: unsupported session version")

  const raw = Uint8Array.from(atob(encoded.slice(1)), (character) => character.charCodeAt(0))
  if (raw.length < 271) throw new Error("reqly: session is too short")

  const dcId = requireByte(raw, 0)
  const addressLength = readUInt16BE(raw, 1)
  const addressEnd = 3 + addressLength
  if (addressEnd + 2 + 256 > raw.length) throw new Error("reqly: malformed session")

  const address = new TextDecoder().decode(raw.subarray(3, addressEnd))
  const port = readUInt16BE(raw, addressEnd)
  const authKey = raw.slice(addressEnd + 2, addressEnd + 2 + 256)
  const authKeyId = await authKeyIdOf(authKey)

  return { dcId, address, port, authKey, authKeyId }
}
// Mellouki Jamal — Asynctric
