/**
 * reqly — a small MTProto 2.0 request/reply client.
 *
 * Copyright (c) 2026 Mellouki Jamal, Asynctric.
 * Licensed under ASYNCTRIC-1.0. Author and platform identity must be preserved.
 */

export { Reqly, type ReqlyOptions } from "./client"
export { RpcError, FileReferenceExpiredError, FileMigrateError, rpcError } from "./errors"
export { decodeFileHashes, getFileHashes, sha256, verifyChunk, type FileHashEntry } from "./hashes"
export { parseSession, type Session } from "./session"
export { SessionStore } from "./sessions"
export { ChunkReader, createChunkReader, STREAM_MB, type StreamOptions } from "./stream"
export { TlReader, TlWriter, IDs, decodeFile, extractDocuments, type RemoteDocument } from "./tl"
export {
  deriveKeys,
  messageKeyOf,
  sha1,
  igeEncrypt,
  igeDecrypt,
  ctrTransform,
  setIgeProvider,
  type IgeProvider,
  type DerivedKeys,
} from "./crypto"
export { call, Connection, MessageIds, type Envelope, type CallOptions } from "./transport"
export { enableWasmCrypto } from "./wasm"
export {
  DH_CONST,
  reqPqEnvelope,
  parseResPq,
  factorPq,
  modPow,
  bigIntBytes,
  plainEnvelope,
  pqInnerDataDc,
  reqDhParamsEnvelope,
  parseServerDhParamsOk,
  parseServerDhInnerData,
  clientDhInnerData,
  setClientDhParamsEnvelope,
  parseDhGenResult,
  type ResPq,
  type ServerDhParamsOk,
  type ServerDhInnerData,
  type DhGenOk,
} from "./dh"
export {
  rsaKeyFromBytes,
  rsaPad,
  temporaryAes,
  decryptServerDh,
  encryptClientDh,
  computeAuthKey,
  bytesToBigInt,
  type RsaPublicKey,
} from "./handshake"
export { TELEGRAM_RSA_KEYS, findTelegramKey, type RsaKeyMaterial } from "./rsa"

export const version = "1.0.0"
export const author = "Mellouki Jamal"
export const platform = "Asynctric"
// Mellouki Jamal — Asynctric
