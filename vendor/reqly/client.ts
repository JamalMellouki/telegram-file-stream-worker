/**
 * High-level reqly client.
 *
 * The transport handles one RPC per socket, including salt corrections,
 * message acknowledgements and container decoding. This layer only wraps the
 * first call in invokeWithLayer/initConnection and exposes typed helpers.
 */

import { TlWriter, TlReader, IDs, decodeFile, extractDocuments, type RemoteDocument } from "./tl"
import { Connection, call, MessageIds, type CallResult } from "./transport"
import { parseSession, type Session } from "./session"
import { SessionStore } from "./sessions"
import { rpcError, FileMigrateError, FloodWaitError } from "./errors"

const INIT_CONNECTION = 0xc1cd5ea9
const INVOKE_WITH_LAYER = 0xda9b0d0d
const TL_LAYER = 233

/** Telegram WebSocket front doors, one per production data center. */
const DC_HOSTS: Record<number, string> = {
  1: "pluto.web.telegram.org",
  2: "venus.web.telegram.org",
  3: "aurora.web.telegram.org",
  4: "vesta.web.telegram.org",
  5: "flora.web.telegram.org",
}

export interface ParallelOptions {
  /** Starting number of concurrent chunk requests. Defaults to 2. */
  minWorkers?: number
  /** Concurrency ceiling. Defaults to 4 (Telegram throttles above this). */
  maxWorkers?: number
  /** Retries per failed chunk before surfacing the error. Defaults to 3. */
  retries?: number
  /** Custom chunk fetcher (e.g. one that reads from a cache). Defaults to getFile. */
  fetch?: (range: { offset: number; limit: number }) => Promise<Uint8Array>
}

export interface ReqlyOptions {
  timeoutMs?: number
  address?: string
  port?: number
  apiId?: number
  dcSessions?: Record<number, string>
  /** Use one socket per RPC instead of a reusable connection (parallel bursts). */
  freshSocket?: boolean
}

function isProtocolError(error: unknown): error is Error & { code: number; telegramMessage: string } {
  return error instanceof Error && typeof (error as { code?: unknown }).code === "number" && typeof (error as { telegramMessage?: unknown }).telegramMessage === "string"
}

/** Transient wire failures are safe to retry; RPC errors are not. */
function isTransportError(error: unknown): boolean {
  if (!(error instanceof Error) || isProtocolError(error)) return false
  return [
    "reqly: RPC timed out",
    "reqly: connection closed",
    "reqly: websocket failed",
    "reqly: unexpected auth key id",
    "reqly: message key mismatch",
    "reqly: session mismatch",
    "reqly: invalid abridged frame",
    "reqly: Telegram rejected the request",
  ].includes(error.message)
}

export class Reqly {
  private initialized = false
  private readonly initializedDcs = new Set<number>()
  private readonly connections = new Map<number, Connection>()
  private readonly dcStore: SessionStore
  private readonly timeoutMs: number | undefined
  private readonly apiId: number
  private readonly freshSocket: boolean

  private constructor(
    private readonly session: Session,
    options: ReqlyOptions,
  ) {
    this.timeoutMs = options.timeoutMs
    // Telegram does not validate api_id for read-only calls; set your own
    // from my.telegram.org for full compatibility with API methods.
    this.apiId = options.apiId ?? 1
    this.freshSocket = options.freshSocket ?? true
    this.dcStore = new SessionStore(session)
  }

  static async connect(encodedSession: string, options: ReqlyOptions = {}): Promise<Reqly> {
    const session = await parseSession(encodedSession)
    if (options.address !== undefined) session.address = options.address
    if (options.port !== undefined) session.port = options.port
    const client = new Reqly(session, options)
    for (const encoded of Object.values(options.dcSessions ?? {})) await client.dcStore.add(encoded)
    return client
  }

  getDcIds(): number[] {
    return this.dcStore.list()
  }

  /** One reusable connection per DC; created lazily on first use. */
  private async connectionFor(session: Session): Promise<Connection> {
    let connection = this.connections.get(session.dcId)
    if (!connection || connection.isClosed()) {
      connection = await Connection.open(session, this.timeoutMs ?? 20000)
      this.connections.set(session.dcId, connection)
    }
    return connection
  }

  async invoke(method: Uint8Array, session: Session = this.session): Promise<Uint8Array> {
    if (this.freshSocket) {
      let outgoing = method
      if (!this.initialized) {
        const init = new TlWriter().uint(INIT_CONNECTION).uint(0).int(this.apiId)
          .string("reqly").string("1.0.0").string("1.0.0").string("en").string("").string("en").raw(method).result()
        outgoing = new TlWriter().uint(INVOKE_WITH_LAYER).int(TL_LAYER).raw(init).result()
        this.initialized = true
      }
      let result: CallResult | undefined
      let lastError: unknown
      for (let attempt = 0; attempt < 4; attempt += 1) {
        try {
          result = await call(session, outgoing, { timeoutMs: this.timeoutMs, ids: new MessageIds() })
          break
        } catch (error) {
          if (isProtocolError(error)) throw rpcError(error.code, error.telegramMessage)
          lastError = error
          if (!isTransportError(error)) throw error
          this.initialized = false
        }
      }
      if (!result) throw lastError
      return result.body
    }
    let needsInit = !this.initializedDcs.has(session.dcId)
    let result: Uint8Array | undefined
    let lastError: unknown
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        const connection = await this.connectionFor(session)
        let outgoing = method
        if (needsInit) {
          const init = new TlWriter()
            .uint(INIT_CONNECTION)
            .uint(0)
            .int(this.apiId)
            .string("reqly")
            .string("1.0.0")
            .string("1.0.0")
            .string("en")
            .string("")
            .string("en")
            .raw(method)
            .result()
          outgoing = new TlWriter().uint(INVOKE_WITH_LAYER).int(TL_LAYER).raw(init).result()
        }
        result = await connection.call(outgoing, this.timeoutMs ?? 20000)
        this.initializedDcs.add(session.dcId)
        break
      } catch (error) {
        if (isProtocolError(error)) {
          const structured = rpcError(error.code, error.telegramMessage)
          if (structured instanceof FloodWaitError && structured.seconds <= 30) {
            lastError = structured
            await new Promise((resolve) => setTimeout(resolve, (structured.seconds + 1) * 1000))
            continue
          }
          throw structured
        }
        lastError = error
        if (!isTransportError(error)) throw error
        // A dropped socket is transparently replaced on the next attempt.
        if (error instanceof Error && error.message === "reqly: connection closed") {
          this.connections.delete(session.dcId)
          needsInit = true
          this.initializedDcs.delete(session.dcId)
        }
        await new Promise((resolve) => setTimeout(resolve, 100 * (attempt + 1)))
      }
    }
    if (!result) throw lastError
    return result
  }

  /** Closes all reusable sockets. Call at the end of a Worker request. */
  close(): void {
    for (const connection of this.connections.values()) connection.close()
    this.connections.clear()
  }

  async getMessages(channelId: bigint, accessHash: bigint, messageIds: readonly number[]): Promise<RemoteDocument[]> {
    const peer = new TlWriter().uint(IDs.peerChannel).long(channelId).long(accessHash).result()
    const writer = new TlWriter()
      .uint(IDs.channelsGetMessages)
      .raw(peer)
      .uint(IDs.vector)
      .uint(messageIds.length)
    for (const id of messageIds) writer.uint(IDs.inputMessageID).int(id)
    return extractDocuments(await this.invoke(writer.result()))
  }

  async getFile(
    location: RemoteDocument,
    offset: number,
    limit: number,
    refresh?: () => Promise<RemoteDocument>,
  ): Promise<Uint8Array> {
    let reference = location.fileReference
    let activeSession = this.session
    let migrated = false

    // Telegram stores files in 1 MB blocks and rejects a single upload.getFile
    // call that crosses a block boundary with LIMIT_INVALID. Split any request
    // at block boundaries so arbitrary ranges always work.
    const BLOCK = 1024 * 1024
    const ALIGN = 4096
    const alignedStart = Math.floor(offset / ALIGN) * ALIGN
    const skip = offset - alignedStart
    let cursor = alignedStart
    let remaining = skip + limit
    let first = true
    const parts: Uint8Array[] = []

    while (remaining > 0 && cursor < location.size) {
      const blockEnd = Math.floor(cursor / BLOCK) * BLOCK + BLOCK
      const inBlock = blockEnd - cursor
      const wanted = Math.min(remaining, inBlock)
      const chunkLimit = Math.max(ALIGN, Math.ceil(wanted / ALIGN) * ALIGN)

      let bytes: Uint8Array | undefined
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const writer = new TlWriter()
          .uint(IDs.uploadGetFile)
          .int(0x01)
          .uint(IDs.inputDocumentFileLocation)
          .long(location.id)
          .long(location.accessHash)
          .bytes(reference)
          .string("")
          .long(BigInt(cursor))
          .int(chunkLimit)
        try {
          bytes = decodeFile(await this.invoke(writer.result(), activeSession))
          break
        } catch (error) {
          if (error instanceof Error && error.name === "FileReferenceExpiredError" && refresh && attempt === 0) {
            reference = (await refresh()).fileReference
            continue
          }
          if (error instanceof FileMigrateError && !migrated) {
            const target = this.dcStore.get(error.dcId)
            if (!target) throw error
            activeSession = target
            migrated = true
            continue
          }
          throw error
        }
      }
      if (!bytes || bytes.length === 0) break

      const from = first ? skip : 0
      const take = Math.min(remaining - from, bytes.length - from)
      if (take > 0) parts.push(bytes.subarray(from, from + take))
      remaining -= from + take
      cursor += bytes.length
      // A short read means the server reached end-of-file; do not request past it.
      if (bytes.length < chunkLimit) remaining = 0
      first = false
    }

    const total = parts.reduce((sum, part) => sum + part.length, 0)
    const output = new Uint8Array(total)
    let position = 0
    for (const part of parts) {
      output.set(part, position)
      position += part.length
    }
    return output
  }

  /**
   * Downloads many byte ranges with an adaptive worker pool.
   *
   * Telegram rate-limits parallel downloads and answers excess concurrency
   * with an error rather than a slower response. This pool therefore starts
   * conservatively (2), grows only after a clean streak, and immediately
   * halves itself on any transport failure — the same strategy used by the
   * official Telegram Web media loader.
   */
  async getFilesParallel(
    location: RemoteDocument,
    ranges: readonly { offset: number; limit: number }[],
    options: ParallelOptions = {},
  ): Promise<Uint8Array[]> {
    const minWorkers = Math.max(1, options.minWorkers ?? 2)
    const maxWorkers = Math.max(minWorkers, options.maxWorkers ?? 4)
    const retries = Math.max(0, options.retries ?? 3)
    const results = new Array<Uint8Array>(ranges.length)
    const failures = new Array<number>(ranges.length).fill(0)
    const pending = ranges.map((_, index) => index)
    let workers = minWorkers
    let cleanStreak = 0
    let cursor = 0
    let lastError: unknown

    const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

    let active = 0
    const worker = async (): Promise<void> => {
      for (;;) {
        while (active >= workers) await sleep(10)
        if (cursor >= pending.length) return
        active += 1
        const index = pending[cursor++]!
        const range = ranges[index]!
        try {
          results[index] = options.fetch
            ? await options.fetch(range)
            : await this.getFile(location, range.offset, range.limit)
          cleanStreak += 1
          if (cleanStreak >= 4 && workers < maxWorkers) {
            workers += 1
            cleanStreak = 0
          }
        } catch (error) {
          lastError = error
          if (!isTransportError(error)) throw error
          workers = Math.max(1, Math.floor(workers / 2))
          cleanStreak = 0
          failures[index] = (failures[index] ?? 0) + 1
          if (failures[index]! > retries) throw error
          await sleep(80 * failures[index]!)
          pending.push(index)
        } finally {
          active -= 1
        }
      }
    }

    await Promise.all(Array.from({ length: maxWorkers }, () => worker()))
    if (results.some((result) => result === undefined)) throw lastError ?? new Error("reqly: parallel download incomplete")
    return results
  }
}
// Mellouki Jamal — Asynctric
