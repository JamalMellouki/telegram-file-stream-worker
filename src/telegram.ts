/**
 * Telegram access for the production stream workers, backed entirely by reqly.
 * No third-party MTProto library is used at runtime.
 */

import { Reqly, createChunkReader, type RemoteDocument } from "../vendor/reqly/index"
import type { Env } from "./types"

const SESSION_KEY = "mtproto:session"
const CHUNK = 1048576
const ALIGN = 4096
const CACHE_TTL = 86400

export interface FileRef {
  location: RemoteDocument
  size: number
  mime: string
}

function dcSessions(env: Env): Record<number, string> {
  const result: Record<number, string> = {}
  for (const dcId of [1, 2, 3]) {
    const value = (env as unknown as Record<string, string>)[`DC${dcId}_SESSION`]
    if (value) result[dcId] = value
  }
  return result
}

export async function getClient(env: Env): Promise<Reqly> {
  // Prefer the injected, verified session. KV may hold a legacy teleproto
  // session from an older deployment, which Telegram rejects.
  const saved = env.MT_SESSION || (await env.SESSIONS.get(SESSION_KEY))
  if (!saved) throw new Error("missing_session")
  return Reqly.connect(saved, {
    timeoutMs: 25000,
    dcSessions: dcSessions(env),
    apiId: Number(env.TELEGRAM_API_ID ?? 1),
  })
}

function channelId(env: Env): bigint {
  const raw = env.ARCHIVE_CHANNEL_ID.replace(/^-100/, "")
  return BigInt(raw)
}

export async function resolveLocation(env: Env, client: Reqly, messageId: number): Promise<FileRef> {
  const accessHash = BigInt(env.CHANNEL_ACCESS_HASH || "6182339367879685909")
  const documents = await client.getMessages(channelId(env), accessHash, [messageId])
  const document = documents[0]
  if (!document) throw new Error("missing_document")
  const size = Number(document.size)
  if (!(size > 0)) throw new Error("empty_document")
  return {
    location: document,
    size,
    mime: size > 0 ? "video/mp4" : "video/mp4",
  }
}

export async function* chunks(
  env: Env,
  client: Reqly,
  ref: FileRef,
  messageId: number,
  start: number,
  end: number,
  chunkSize: number,
): AsyncGenerator<Uint8Array> {
  void messageId
  const reader = createChunkReader(client, ref.location, {
    chunkSize,
    minWorkers: 2,
    maxWorkers: 4,
  })
  if (start === 0) await reader.prefetchTail(ref.size)
  const block = await reader.readRange(start, end)
  if (block.length > 0) yield block
}

// Made By MELLOUKI JAMAL
