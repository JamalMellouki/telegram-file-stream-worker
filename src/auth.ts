export interface SignedRequest {
  internalId: string
  messageId: number
  exp: number
  nonce: string
  title: string
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer)).map((byte) => byte.toString(16).padStart(2, "0")).join("")
}

async function sign(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
  return toHex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)))
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let index = 0; index < a.length; index += 1) diff |= a.charCodeAt(index) ^ b.charCodeAt(index)
  return diff === 0
}

export async function verify(url: URL, secret: string): Promise<SignedRequest | null> {
  const id = url.searchParams.get("id") ?? ""
  const mid = url.searchParams.get("mid") ?? ""
  const exp = url.searchParams.get("exp") ?? ""
  const nonce = url.searchParams.get("nonce") ?? ""
  const title = url.searchParams.get("title") ?? ""
  const sig = url.searchParams.get("sig") ?? ""

  if (!/^\d+$/.test(exp) || Date.now() > Number(exp)) return null
  if (!/^\d{10}$/.test(id) || !/^\d+$/.test(mid) || !/^[a-f0-9]{24}$/.test(nonce)) return null
  if (!/^[a-f0-9]{64}$/.test(sig)) return null

  const expected = await sign(secret, `${id}.${mid}.${exp}.${nonce}.${title}`)
  const legacy = await sign(secret, `${id}.${mid}.${exp}.${nonce}`)
  if (!constantTimeEqual(expected, sig) && !constantTimeEqual(legacy, sig)) return null

  return { internalId: id, messageId: Number(mid), exp: Number(exp), nonce, title }
}
// Made By MELLOUKI JAMAL
