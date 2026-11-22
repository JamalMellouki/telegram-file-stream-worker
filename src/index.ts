import aesWasm from "../aes-ige.wasm"
import { enableWasmCrypto } from "../vendor/reqly/index"
import { verify } from "./auth"
import { parseRange } from "./range"
import { chunks, getClient, resolveLocation, type FileRef } from "./telegram"
import type { Env } from "./types"

export { StreamCoordinator } from "./coordinator"

enableWasmCrypto(aesWasm)

function json(body: unknown, status = 200): Response {
  const headers = new Headers({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "access-control-allow-origin": "*" })
  return new Response(JSON.stringify(body), { status, headers })
}

async function handle(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url)
  const segment = url.pathname.split("/").filter(Boolean)[0] ?? ""

  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { "access-control-allow-origin": "*", "access-control-allow-methods": "GET, OPTIONS", "access-control-allow-headers": "range, content-type" } })
  if (request.method !== "GET") return json({ error: "method_not_allowed" }, 405)
  if (segment === "health") return json({ ok: true, worker: env.WORKER_NAME })
  if (segment !== "stream" && segment !== "download") return json({ error: "not_found" }, 404)

  const signed = await verify(url, env.SIGNING_SECRET)
  if (!signed) return json({ error: "unauthorized" }, 403)

  let client
  let ref: FileRef
  try {
    client = await getClient(env)
    ref = await resolveLocation(env, client, signed.messageId)
  } catch (error) {
    if (client) {
      try {
        client.close()
      } catch {}
    }
    await env.SESSIONS.delete("mtproto:session")
    return json({ error: "telegram_unavailable", detail: error instanceof Error ? error.message : String(error) }, 502)
  }

  if (ref.size <= 0) return json({ error: "empty_file" }, 502)
  const range = parseRange(request.headers.get("range"), ref.size)
  if (!range) return json({ error: "invalid_range" }, 416)

  const maxBytes = Math.max(65536, Math.min(8 * 1024 * 1024, Number(env.MAX_BYTES ?? "2097152")))
  range.end = Math.min(range.end, range.start + maxBytes - 1, ref.size - 1)
  const length = range.end - range.start + 1
  const source = chunks(env, client, ref, signed.messageId, range.start, range.end, 65536)
  const iterator = (async function* () {
    try {
      for await (const value of source) {
        yield value
        await new Promise((resolve) => setTimeout(resolve, 0))
      }
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

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return handle(request, env).catch((error: unknown) => json({ error: "internal_error", detail: error instanceof Error ? error.message : String(error) }, 500))
  },
}
// Made By MELLOUKI JAMAL
