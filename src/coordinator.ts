import { DurableObject } from "cloudflare:workers"
import { verify } from "./auth"
import { parseRange } from "./range"
import { chunks, getClient, resolveLocation, type FileRef } from "./telegram"
import type { Env } from "./types"

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } })
}

export class StreamCoordinator extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url)
    const segment = url.pathname.split("/").filter(Boolean)[0] ?? ""
    const signed = await verify(url, this.env.SIGNING_SECRET)
    if (!signed) return json({ error: "unauthorized" }, 403)

    let client
    let ref: FileRef
    try {
      client = await getClient(this.env)
      ref = await resolveLocation(this.env, client, signed.messageId)
    } catch (error) {
      if (client) {
        try {
          client.close()
        } catch {}
      }
      await this.env.SESSIONS.delete("mtproto:session")
      return json({ error: "telegram_unavailable", detail: error instanceof Error ? error.message : String(error) }, 502)
    }

    if (ref.size <= 0) return json({ error: "empty_file" }, 502)
    const range = parseRange(request.headers.get("range"), ref.size)
    if (!range) return json({ error: "invalid_range" }, 416)

    const length = range.end - range.start + 1
    const chunkSize = Math.max(65536, Math.min(262144, Number(this.env.CHUNK_SIZE ?? "262144")))
    const source = chunks(this.env, client, ref, signed.messageId, range.start, range.end, chunkSize)
    const iterator = (async function* () {
      try {
        yield* source
      } finally {
        client.close()
      }
    })()
    const body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const next = await iterator.next()
          if (next.done) controller.close()
          else controller.enqueue(next.value)
        } catch (error) {
          controller.error(error)
        }
      },
      async cancel() {
        await iterator.return?.(undefined)
        client.close()
      },
    })

    const headers = new Headers({
      "content-type": ref.mime || "video/mp4",
      "accept-ranges": "bytes",
      "content-length": String(length),
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
    })
    if (range.partial) headers.set("content-range", `bytes ${range.start}-${range.end}/${ref.size}`)
    if (segment === "download") {
      const name = signed.title || signed.internalId
      const ascii = name.replace(/[^\x20-\x7E]/g, "").replace(/["\\]/g, "_").trim() || signed.internalId
      headers.set("content-disposition", `attachment; filename="${ascii}.mp4"; filename*=UTF-8''${encodeURIComponent(name)}.mp4`)
    }
    return new Response(body, { status: range.partial ? 206 : 200, headers })
  }
}
// Made By MELLOUKI JAMAL
