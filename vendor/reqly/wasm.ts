/**
 * Optional WASM-backed AES-256-IGE provider.
 *
 * The module is fetched at runtime from a build-time asset so bundlers and
 * test runners do not need special WASM import plugins. Pure-JS IGE remains
 * the default and needs no external asset.
 */

import { setIgeProvider, type IgeProvider } from "./crypto"

interface IgeEngine {
  memory: WebAssembly.Memory
  state_ptr(): number
  state_size(): number
  state_cipher_size(): number
  key_ptr(): number
  iv_ptr(): number
  input_ptr(): number
  input_capacity(): number
  init(length: number): number
  ige_encrypt(length: number): number
  ige_decrypt(length: number): number
}

function transform(engine: IgeEngine, data: Uint8Array, key: Uint8Array, iv: Uint8Array, decrypting: boolean): Uint8Array {
  const memory = new Uint8Array(engine.memory.buffer)
  const stateOffset = engine.state_ptr()
  const stateSize = engine.state_size()
  const cipherSize = engine.state_cipher_size()
  const keyOffset = engine.key_ptr()
  const ivOffset = engine.iv_ptr()
  const inputOffset = engine.input_ptr()
  const inputCapacity = engine.input_capacity()
  const operation = decrypting ? engine.ige_decrypt : engine.ige_encrypt
  const output = new Uint8Array(data.length)

  memory.set(key, keyOffset)
  if (engine.init(key.length) !== 0) throw new Error("reqly: WASM AES initialization failed")
  const cipherState = memory.slice(stateOffset, stateOffset + cipherSize)
  memory.fill(0, keyOffset, keyOffset + 32)
  memory.fill(0, stateOffset, stateOffset + stateSize)

  try {
    memory.set(cipherState, stateOffset)
    memory.set(iv, ivOffset)
    for (let offset = 0; offset < data.length; offset += inputCapacity) {
      const chunk = data.subarray(offset, offset + inputCapacity)
      memory.set(chunk, inputOffset)
      if (operation(chunk.length) !== 0) throw new Error("reqly: WASM AES operation failed")
      output.set(memory.subarray(inputOffset, inputOffset + chunk.length), offset)
    }
    return output
  } finally {
    memory.fill(0, stateOffset, stateOffset + stateSize)
    memory.fill(0, inputOffset, inputOffset + Math.min(data.length, inputCapacity))
    cipherState.fill(0)
  }
}

let enabled = false

/** Installs the WASM provider. Requires an `aesWasmModule: WebAssembly.Module` binding. */
export function enableWasmCrypto(module: WebAssembly.Module): void {
  if (enabled) return
  const engine = new WebAssembly.Instance(module).exports as unknown as IgeEngine
  const provider: IgeProvider = {
    encrypt: (data, key, iv) => transform(engine, data, key, iv, false),
    decrypt: (data, key, iv) => transform(engine, data, key, iv, true),
  }
  setIgeProvider(provider)
  enabled = true
}
// Mellouki Jamal — Asynctric
