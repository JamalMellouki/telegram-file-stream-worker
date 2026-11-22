/**
 * Structured Telegram RPC errors.
 *
 * The named codes come from core.telegram.org/api/errors and the file download
 * section of core.telegram.org/api/files. Keeping them typed lets callers react
 * without string matching on English messages.
 */

export class RpcError extends Error {
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(message)
    this.name = "RpcError"
  }
}

export class FileReferenceExpiredError extends RpcError {
  constructor() {
    super(400, "FILE_REFERENCE_EXPIRED")
    this.name = "FileReferenceExpiredError"
  }
}

export class FileMigrateError extends RpcError {
  constructor(readonly dcId: number) {
    super(400, `FILE_MIGRATE_${dcId}`)
    this.name = "FileMigrateError"
  }
}

export function rpcError(code: number, message: string): Error {
  if (message === "FILE_REFERENCE_EXPIRED" || message === "FILE_REFERENCE_INVALID") return new FileReferenceExpiredError()
  const migrate = /^FILE_MIGRATE_(\d+)$/.exec(message)
  if (migrate) return new FileMigrateError(Number(migrate[1]))
  return new RpcError(code, message)
}
// Mellouki Jamal — Asynctric
