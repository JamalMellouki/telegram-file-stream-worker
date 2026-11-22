/**
 * Verification of downloaded file chunks.
 *
 * Telegram recommends checking each part against the SHA-256 values returned
 * by upload.getFileHashes (core.telegram.org/method/upload.getFileHashes).
 */

import { TlReader, TlWriter, IDs } from "./tl"
import type { RemoteDocument } from "./tl"
import type { Reqly } from "./client"

export interface FileHashEntry {
  offset: number
  limit: number
  hash: Uint8Array
}

/** Parses a vector<fileHash> reply from upload.getFileHashes. */
export function decodeFileHashes(payload: Uint8Array): FileHashEntry[] {
  const reader = new TlReader(payload)
  if (reader.uint() !== IDs.vector) throw new Error("reqly: expected vector<fileHash>")
  const count = reader.uint()
  const entries: FileHashEntry[] = []
  for (let index = 0; index < count; index += 1) {
    const ctor = reader.uint()
    if (ctor !== 0xf39b035c) throw new Error(`reqly: unexpected fileHash constructor 0x${ctor.toString(16)} at index ${index} pos ${reader.position}`)
    const offset = Number(reader.long())
    const limit = reader.int()
    entries.push({ offset, limit, hash: reader.bytes() })
  }
  return entries
}

/** Returns the hashes covering the given byte range, or an empty list. */
export async function getFileHashes(client: Reqly, location: RemoteDocument, offset: number): Promise<FileHashEntry[]> {
  const locationBytes = new TlWriter()
    .uint(IDs.inputDocumentFileLocation)
    .long(location.id)
    .long(location.accessHash)
    .bytes(location.fileReference)
    .string("")
    .result()
  const method = new TlWriter().uint(0x9156982a).raw(locationBytes).long(BigInt(offset)).result()
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const reply = await client.invoke(method)
    try {
      return decodeFileHashes(reply)
    } catch (error) {
      if (attempt === 2) throw error
    }
  }
  throw new Error("reqly: getFileHashes failed")
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as unknown as BufferSource))
}

/** Verifies a downloaded chunk against a hash entry. Returns true on match. */
export async function verifyChunk(data: Uint8Array, entry: FileHashEntry): Promise<boolean> {
  if (entry.limit !== data.length) return false
  const digest = await sha256(data)
  if (digest.length !== entry.hash.length) return false
  let difference = 0
  for (let index = 0; index < digest.length; index += 1) difference |= digest[index]! ^ entry.hash[index]!
  return difference === 0
}
// Mellouki Jamal — Asynctric
