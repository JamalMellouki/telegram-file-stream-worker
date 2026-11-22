import { Reqly } from "../vendor/reqly/index"

const CHUNK = 1048576
const ALIGN = 4096
const CACHE_TTL = 86400
const PREFETCH_CHUNKS = 8

interface DownloadFile {
  id: bigint
  accessHash: bigint
  fileReference: Uint8Array
  size: bigint
}

export function chunkKey(file: DownloadFile, offset: number): Request {
  return new Request(`https://reqly-chunk.internal/${file.id}/${offset}`)
}

export async function isCold(file: DownloadFile, offset: number): Promise<boolean> {
  try {
    return !(await caches.default.match(chunkKey(file, offset)))
  } catch {
    return true
  }
}

export async function readChunk(client: Reqly, file: DownloadFile, offset: number): Promise<Uint8Array> {
  const key = chunkKey(file, offset)
  try {
    const cached = await caches.default.match(key)
    if (cached) return new Uint8Array(await cached.arrayBuffer())
  } catch { /* cache unavailable */ }

  const bytes = await client.getFile(file, offset, CHUNK)
  try {
    await caches.default.put(key, new Response(bytes.slice().buffer as ArrayBuffer, {
      headers: { "cache-control": `public, max-age=${CACHE_TTL}`, "content-type": "application/octet-stream" },
    }))
  } catch { /* cache full or unavailable; streaming still works */ }
  return bytes
}

/** Warms upcoming chunks in the background so forward playback and seeks are instant. */
export async function prefetchAhead(client: Reqly, file: DownloadFile, from: number): Promise<void> {
  const start = Math.floor(from / CHUNK) * CHUNK
  for (let index = 0; index < PREFETCH_CHUNKS; index += 1) {
    const offset = start + index * CHUNK
    if (BigInt(offset) >= file.size) break
    if (await isCold(file, offset)) await readChunk(client, file, offset).catch(() => undefined)
  }
}

export async function prefetchTail(client: Reqly, file: DownloadFile): Promise<void> {
  const tail = Math.floor((Number(file.size) - 1) / CHUNK) * CHUNK
  if (await isCold(file, tail)) await readChunk(client, file, tail).catch(() => undefined)
}

/** Reads a byte range from 1 MB chunks, served from or written to the edge cache. */
export async function readRange(client: Reqly, file: DownloadFile, start: number, end: number): Promise<Uint8Array> {
  if (start === 0) {
    const tailOffset = Math.floor((Number(file.size) - 1) / CHUNK) * CHUNK
    if (await isCold(file, 0) || await isCold(file, tailOffset)) {
      // The player needs the moov atom at the end before it can start.
      await prefetchTail(client, file)
    }
  }
  const alignedStart = Math.floor(start / ALIGN) * ALIGN
  const skip = start - alignedStart
  const total = skip + (end - start + 1)
  const ranges: Array<{ offset: number; limit: number }> = []
  for (let offset = alignedStart; offset < alignedStart + total; offset += CHUNK) {
    ranges.push({ offset, limit: CHUNK })
  }
  const parts = await client.getFilesParallel(file, ranges, {
    minWorkers: 2,
    maxWorkers: 4,
    fetch: (range) => readChunk(client, file, range.offset),
  })
  const size = parts.reduce((sum, part) => sum + part.length, 0)
  const result = new Uint8Array(size)
  let position = 0
  for (const part of parts) {
    result.set(part, position)
    position += part.length
  }
  return skip === 0 ? result : result.subarray(skip)
}
// Mellouki Jamal — Asynctric
