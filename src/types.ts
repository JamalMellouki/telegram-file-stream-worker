export interface Env {
  SIGNING_SECRET: string
  BOT_TOKEN: string
  TELEGRAM_API_ID: string
  TELEGRAM_API_HASH: string
  MT_SESSION: string
  DC1_SESSION: string
  DC2_SESSION: string
  DC3_SESSION: string
  CHANNEL_ACCESS_HASH: string
  ARCHIVE_CHANNEL_ID: string
  WORKER_NAME: string
  CHUNK_SIZE: string
  MAX_BYTES: string
  SESSIONS: KVNamespace
  STREAM_COORDINATOR: DurableObjectNamespace
}
// Made By MELLOUKI JAMAL
