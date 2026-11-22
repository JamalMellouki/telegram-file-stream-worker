/**
 * Telegram access for the production stream workers, backed entirely by reqly.
 * No third-party MTProto library is used at runtime.
 */

import { Reqly, type RemoteDocument } from "../vendor/reqly/index"
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
  const accessHash = BigInt(env.CHANNEL_ACCESS_HASH)
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

function chunkKey(location: RemoteDocument, offset: number): Request {
  return new Request(`https://reqly-chunk.internal/${location.id}/${offset}`)
}

async function readChunk(client: Reqly, location: RemoteDocument, offset: number): Promise<Uint8Array> {
  const key = chunkKey(location, offset)
  try {
    const cached = await caches.default.match(key)
    if (cached) return new Uint8Array(await cached.arrayBuffer())
  } catch { /* cache unavailable */ }

  const bytes = await client.getFile(location, offset, CHUNK)
  try {
    await caches.default.put(key, new Response(bytes.slice().buffer as ArrayBuffer, {
      headers: { "cache-control": `public, max-age=${CACHE_TTL}`, "content-type": "application/octet-stream" },
    }))
  } catch { /* cache full or unavailable */ }
  return bytes
}

/** Pre-warms the moov tail so the player can start without a second slow fetch. */
async function prefetchTail(client: Reqly, location: RemoteDocument, size: number): Promise<void> {
  const tail = Math.floor((size - 1) / CHUNK) * CHUNK
  try {
    if (await caches.default.match(chunkKey(location, tail))) return
    await readChunk(client, location, tail)
  } catch { /* best effort */ }
}

export async function* chunks(
  env: Env,
  client: Reqly,
  ref: FileRef,
  messageId: number,
  start: number,
  end: number,
  _chunkSize: number,
): AsyncGenerator<Uint8Array> {
  void messageId
  if (start === 0) await prefetchTail(client, ref.location, ref.size)

  const alignedStart = Math.floor(start / ALIGN) * ALIGN
  const skip = start - alignedStart
  const total = skip + (end - start + 1)
  const ranges: Array<{ offset: number; limit: number }> = []
  for (let offset = alignedStart; offset < alignedStart + total; offset += CHUNK) {
    ranges.push({ offset, limit: CHUNK })
  }

  const parts = await client.getFilesParallel(ref.location, ranges, {
    minWorkers: 2,
    maxWorkers: 4,
    fetch: (range) => readChunk(client, ref.location, range.offset),
  })

  const size = parts.reduce((sum, part) => sum + part.length, 0)
  const result = new Uint8Array(size)
  let position = 0
  for (const part of parts) {
    result.set(part, position)
    position += part.length
  }
  const output = skip === 0 ? result : result.subarray(skip)
  if (output.length > 0) yield output
}
// Made By MELLOUKI JAMAL
