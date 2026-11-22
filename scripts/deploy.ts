import { spawnSync } from "node:child_process"
import { mkdir, writeFile } from "node:fs/promises"
import { fileURLToPath } from "node:url"
import { dirname, resolve } from "node:path"

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, "..", "..")
;(process as any).loadEnvFile(resolve(root, ".env"))

const API = "https://api.cloudflare.com/client/v4"
const signingSecret = process.env.SIGNING_SECRET ?? ""
if (!signingSecret) throw new Error("SIGNING_SECRET is required")
const apiId = process.env.TELEGRAM_API_ID ?? ""
const apiHash = process.env.TELEGRAM_API_HASH ?? ""
const archiveChat = process.env.ARCHIVE_CHANNEL_ID ?? ""
const mtSession = process.env.MTPROTO_SESSION ?? ""
const dcSessions = {
  DC1_SESSION: process.env.DC1_SESSION ?? "",
  DC2_SESSION: process.env.DC2_SESSION ?? "",
  DC3_SESSION: process.env.DC3_SESSION ?? "",
}
const channelAccessHash = process.env.CHANNEL_ACCESS_HASH ?? ""
if (!channelAccessHash) throw new Error("CHANNEL_ACCESS_HASH is required")

async function cf(path: string, token: string, init?: RequestInit): Promise<any> {
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, "content-type": "application/json", ...(init?.headers ?? {}) },
    signal: AbortSignal.timeout(30000),
  })
  const body = (await response.json().catch(() => ({}))) as any
  if (!response.ok) throw new Error(`${path}: ${body.errors?.[0]?.message ?? response.status}`)
  return body.result
}

await mkdir(resolve(here, "..", "configs"), { recursive: true })

const deployed: Array<{ name: string; url: string; account: number; bot: string }> = []

for (let index = 1; index <= 100; index += 1) {
  const botToken = process.env[`BOT${index}_TOKEN`]
  if (!botToken) break
  const accountNumber = index + 1
  const accountId = process.env[`CF_ACCOUNT_${accountNumber}_ID`]
  const accountToken = process.env[`CF_ACCOUNT_${accountNumber}_TOKEN`]
  if (!accountId || !accountToken) throw new Error(`missing account ${accountNumber}`)

  const name = `str${index}`
  const namespaces = (await cf(`/accounts/${accountId}/storage/kv/namespaces`, accountToken)) as Array<{ id: string; title: string }>
  const title = `stream-sessions-${name}`
  const existing = namespaces.find((namespace) => namespace.title === title)
  const namespaceId = existing?.id ?? ((await cf(`/accounts/${accountId}/storage/kv/namespaces`, accountToken, {
    method: "POST",
    body: JSON.stringify({ title }),
  })) as { id: string }).id

  const subdomain = ((await cf(`/accounts/${accountId}/workers/subdomain`, accountToken)) as { subdomain: string }).subdomain
  const existingScripts = (await cf(`/accounts/${accountId}/workers/scripts`, accountToken)) as Array<{ id: string }>
  const hasExisting = existingScripts.some((script) => script.id === name)
  const config = {
    $schema: "node_modules/wrangler/config-schema.json",
    name,
    account_id: accountId,
    main: "../src/index.ts",
    compatibility_date: "2026-11-21",
    compatibility_flags: ["nodejs_compat"],
    kv_namespaces: [{ binding: "SESSIONS", id: namespaceId }],
    durable_objects: { bindings: [{ name: "STREAM_COORDINATOR", class_name: "StreamCoordinator" }] },
    migrations: [{ tag: "v1", new_sqlite_classes: ["StreamCoordinator"] }],
    vars: {
      SIGNING_SECRET: signingSecret,
      BOT_TOKEN: botToken,
      TELEGRAM_API_ID: apiId,
      TELEGRAM_API_HASH: apiHash,
      MT_SESSION: mtSession,
      ...dcSessions,
      CHANNEL_ACCESS_HASH: channelAccessHash,
      ARCHIVE_CHANNEL_ID: archiveChat,
      WORKER_NAME: name,
      CHUNK_SIZE: "1048576",
      MAX_BYTES: "2097152",
    },
    observability: { enabled: false },
  }
  void hasExisting
  const only = process.env.ONLY_WORKER
  if (only && only !== name) continue
  const configPath = resolve(here, "..", "configs", `wrangler-${name}.jsonc`)
  await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n// Made By MELLOUKI JAMAL\n`)

  const wrangler = resolve(here, "..", "node_modules", ".bin", "wrangler")
  const result = spawnSync(wrangler, ["deploy", "--config", configPath], {
    stdio: "inherit",
    cwd: resolve(here, ".."),
    env: { ...process.env, CLOUDFLARE_API_TOKEN: accountToken, CLOUDFLARE_ACCOUNT_ID: accountId },
  })
  if (result.status !== 0) throw new Error(`deploy failed for ${name}`)

  const url = `https://${name}.${subdomain}.workers.dev`
  deployed.push({ name, url, account: accountNumber, bot: process.env[`BOT${index}_USERNAME`] ?? `bot${index}` })
  console.log(`${name} -> ${url}`)
}

const output = resolve(root, "deployed.json")
await writeFile(output, `${JSON.stringify({ workers: deployed, "//": "Made By MELLOUKI JAMAL" }, null, 2)}\n`)
console.log(`saved ${output} (${deployed.length} workers)`)
// Made By MELLOUKI JAMAL
