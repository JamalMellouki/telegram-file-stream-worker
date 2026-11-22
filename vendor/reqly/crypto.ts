/**
 * MTProto 2.0 cryptographic primitives.
 *
 * The runtime only needs SHA-256 and AES-256. Web Crypto provides the hash;
 * AES-256-IGE is assembled here from a small, auditable block implementation.
 * A platform can replace the IGE provider with a WASM-backed one through
 * `setIgeProvider` without changing any protocol code.
 */

export interface IgeProvider {
  encrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array
  decrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array
}

function multiply(left: number, right: number): number {
  let product = 0
  let a = left
  let b = right
  for (let bit = 0; bit < 8; bit += 1) {
    if ((b & 1) !== 0) product ^= a
    const high = a & 0x80
    a = (a << 1) & 0xff
    if (high !== 0) a ^= 0x1b
    b >>= 1
  }
  return product
}

function buildSboxes(): { forward: Uint8Array; inverse: Uint8Array } {
  const exponent = new Uint8Array(512)
  const logarithm = new Uint8Array(256)
  let value = 1
  for (let index = 0; index < 255; index += 1) {
    exponent[index] = value
    logarithm[value] = index
    value = multiply(value, 3)
  }
  for (let index = 255; index < 512; index += 1) exponent[index] = exponent[index - 255] ?? 0

  const forward = new Uint8Array(256)
  const inverse = new Uint8Array(256)
  for (let candidate = 0; candidate < 256; candidate += 1) {
    const reciprocal = candidate === 0 ? 0 : exponent[255 - (logarithm[candidate] ?? 0)] ?? 0
    const rotate = (byte: number, count: number): number => ((byte << count) | (byte >>> (8 - count))) & 0xff
    const substituted = reciprocal ^ rotate(reciprocal, 1) ^ rotate(reciprocal, 2) ^ rotate(reciprocal, 3) ^ rotate(reciprocal, 4) ^ 0x63
    forward[candidate] = substituted
    inverse[substituted] = candidate
  }
  return { forward, inverse }
}

const boxes = buildSboxes()
const roundConstants = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]

interface BlockCipher {
  encryptBlock(block: Uint8Array): Uint8Array
  decryptBlock(block: Uint8Array): Uint8Array
}

function expandKey(key: Uint8Array): Uint32Array {
  const words = new Uint32Array(60)
  for (let index = 0; index < 8; index += 1) {
    const offset = index * 4
    words[index] = ((key[offset] ?? 0) << 24) | ((key[offset + 1] ?? 0) << 16) | ((key[offset + 2] ?? 0) << 8) | (key[offset + 3] ?? 0)
  }
  for (let index = 8; index < 60; index += 1) {
    let temporary = words[index - 1] ?? 0
    if (index % 8 === 0) {
      temporary = ((temporary << 8) | (temporary >>> 24)) >>> 0
      const bytes = new Uint8Array([(temporary >>> 24) & 0xff, (temporary >>> 16) & 0xff, (temporary >>> 8) & 0xff, temporary & 0xff])
      for (let byte = 0; byte < 4; byte += 1) bytes[byte] = boxes.forward[bytes[byte] ?? 0] ?? 0
      temporary = ((bytes[0] ?? 0) << 24) | ((bytes[1] ?? 0) << 16) | ((bytes[2] ?? 0) << 8) | (bytes[3] ?? 0)
      temporary ^= (roundConstants[index / 8 - 1] ?? 0) << 24
    } else if (index % 8 === 4) {
      const bytes = new Uint8Array([(temporary >>> 24) & 0xff, (temporary >>> 16) & 0xff, (temporary >>> 8) & 0xff, temporary & 0xff])
      for (let byte = 0; byte < 4; byte += 1) bytes[byte] = boxes.forward[bytes[byte] ?? 0] ?? 0
      temporary = ((bytes[0] ?? 0) << 24) | ((bytes[1] ?? 0) << 16) | ((bytes[2] ?? 0) << 8) | (bytes[3] ?? 0)
    }
    words[index] = ((words[index - 8] ?? 0) ^ temporary) >>> 0
  }
  return words
}

function addRoundKey(state: Uint8Array, words: Uint32Array, round: number): void {
  for (let column = 0; column < 4; column += 1) {
    const word = words[round * 4 + column] ?? 0
    for (let row = 0; row < 4; row += 1) {
      const index = column * 4 + row
      state[index] = (state[index] ?? 0) ^ ((word >>> (24 - row * 8)) & 0xff)
    }
  }
}

function mixColumns(state: Uint8Array): void {
  for (let column = 0; column < 4; column += 1) {
    const offset = column * 4
    const a0 = state[offset] ?? 0
    const a1 = state[offset + 1] ?? 0
    const a2 = state[offset + 2] ?? 0
    const a3 = state[offset + 3] ?? 0
    state[offset] = multiply(a0, 2) ^ multiply(a1, 3) ^ a2 ^ a3
    state[offset + 1] = a0 ^ multiply(a1, 2) ^ multiply(a2, 3) ^ a3
    state[offset + 2] = a0 ^ a1 ^ multiply(a2, 2) ^ multiply(a3, 3)
    state[offset + 3] = multiply(a0, 3) ^ a1 ^ a2 ^ multiply(a3, 2)
  }
}

function inverseMixColumns(state: Uint8Array): void {
  for (let column = 0; column < 4; column += 1) {
    const offset = column * 4
    const a0 = state[offset] ?? 0
    const a1 = state[offset + 1] ?? 0
    const a2 = state[offset + 2] ?? 0
    const a3 = state[offset + 3] ?? 0
    state[offset] = multiply(a0, 14) ^ multiply(a1, 11) ^ multiply(a2, 13) ^ multiply(a3, 9)
    state[offset + 1] = multiply(a0, 9) ^ multiply(a1, 14) ^ multiply(a2, 11) ^ multiply(a3, 13)
    state[offset + 2] = multiply(a0, 13) ^ multiply(a1, 9) ^ multiply(a2, 14) ^ multiply(a3, 11)
    state[offset + 3] = multiply(a0, 11) ^ multiply(a1, 13) ^ multiply(a2, 9) ^ multiply(a3, 14)
  }
}

function substitute(state: Uint8Array, table: Uint8Array): void {
  for (let index = 0; index < 16; index += 1) state[index] = table[state[index] ?? 0] ?? 0
}

function shiftRows(state: Uint8Array): void {
  const original = state.slice()
  for (let row = 1; row < 4; row += 1) {
    for (let column = 0; column < 4; column += 1) {
      state[column * 4 + row] = original[((column + row) % 4) * 4 + row] ?? 0
    }
  }
}

function inverseShiftRows(state: Uint8Array): void {
  const original = state.slice()
  for (let row = 1; row < 4; row += 1) {
    for (let column = 0; column < 4; column += 1) {
      state[column * 4 + row] = original[((column - row + 4) % 4) * 4 + row] ?? 0
    }
  }
}

function createBlockCipher(key: Uint8Array): BlockCipher {
  const words = expandKey(key)
  return {
    encryptBlock(block: Uint8Array): Uint8Array {
      const state = block.slice()
      addRoundKey(state, words, 0)
      for (let round = 1; round < 14; round += 1) {
        substitute(state, boxes.forward)
        shiftRows(state)
        mixColumns(state)
        addRoundKey(state, words, round)
      }
      substitute(state, boxes.forward)
      shiftRows(state)
      addRoundKey(state, words, 14)
      return state
    },
    decryptBlock(block: Uint8Array): Uint8Array {
      const state = block.slice()
      addRoundKey(state, words, 14)
      for (let round = 13; round >= 1; round -= 1) {
        inverseShiftRows(state)
        substitute(state, boxes.inverse)
        addRoundKey(state, words, round)
        inverseMixColumns(state)
      }
      inverseShiftRows(state)
      substitute(state, boxes.inverse)
      addRoundKey(state, words, 0)
      return state
    },
  }
}

function xor(first: Uint8Array, second: Uint8Array): Uint8Array {
  const output = new Uint8Array(first.length)
  for (let index = 0; index < first.length; index += 1) output[index] = (first[index] ?? 0) ^ (second[index] ?? 0)
  return output
}

function ige(data: Uint8Array, key: Uint8Array, iv: Uint8Array, decrypting: boolean): Uint8Array {
  if (data.length % 16 !== 0) throw new Error("reqly: IGE input must be block aligned")
  if (iv.length !== 32) throw new Error("reqly: IGE IV must be 32 bytes")
  const cipher = createBlockCipher(key)
  const output = new Uint8Array(data.length)
  let previousCipher: Uint8Array<ArrayBufferLike> = iv.slice(0, 16)
  let previousPlain: Uint8Array<ArrayBufferLike> = iv.slice(16, 32)
  for (let offset = 0; offset < data.length; offset += 16) {
    const block = data.slice(offset, offset + 16)
    if (decrypting) {
      const plain = xor(cipher.decryptBlock(xor(block, previousPlain)), previousCipher)
      output.set(plain, offset)
      previousPlain = plain
      previousCipher = block
    } else {
      const encrypted = xor(cipher.encryptBlock(xor(block, previousCipher)), previousPlain)
      output.set(encrypted, offset)
      previousPlain = block
      previousCipher = encrypted
    }
  }
  return output as Uint8Array<ArrayBufferLike>
}

let provider: IgeProvider = { encrypt: (data, key, iv) => ige(data, key, iv, false), decrypt: (data, key, iv) => ige(data, key, iv, true) }

export function setIgeProvider(next: IgeProvider): void {
  provider = next
}

export function igeEncrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  return provider.encrypt(data, key, iv)
}

export function igeDecrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  return provider.decrypt(data, key, iv)
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const joined = new Uint8Array(total)
  let cursor = 0
  for (const part of parts) {
    joined.set(part, cursor)
    cursor += part.length
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", joined))
}

export interface DerivedKeys {
  key: Uint8Array
  iv: Uint8Array
}

/** MTProto 2.0 key derivation. `direction` is 0 for client-to-server, 8 for the reverse. */
export async function deriveKeys(authKey: Uint8Array, messageKey: Uint8Array, direction: number): Promise<DerivedKeys> {
  const hashA = await sha256(messageKey, authKey.subarray(direction, direction + 36))
  const hashB = await sha256(authKey.subarray(40 + direction, 76 + direction), messageKey)
  return {
    key: new Uint8Array([...hashA.slice(0, 8), ...hashB.slice(8, 24), ...hashA.slice(24, 32)]),
    iv: new Uint8Array([...hashB.slice(0, 8), ...hashA.slice(8, 24), ...hashB.slice(24, 32)]),
  }
}

export async function sha1(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-1", data as unknown as BufferSource))
}

export async function messageKeyOf(authKey: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const digest = await sha256(authKey.subarray(88, 120), plaintext)
  return digest.slice(8, 24)
}

/** AES-256-CTR keystream used by MTProto transport obfuscation. */
export async function ctrTransform(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey("raw", key as unknown as BufferSource, { name: "AES-CTR" }, false, ["encrypt"])
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CTR", counter: iv as unknown as BufferSource, length: 128 }, imported, data as unknown as BufferSource))
}
// Mellouki Jamal — Asynctric
