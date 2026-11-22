/**
 * Per-datacenter session registry.
 *
 * Telegram stores each file in a specific data center and refuses downloads
 * from any other one (FILE_MIGRATE_X). A session's auth key cannot be reused
 * across DCs, so reqly keeps one already-authorized session per DC and picks
 * the matching one when a migration error is received. Sessions are generated
 * once in Node (see scripts/gen-dc-sessions.ts) and injected by the caller.
 */

import { parseSession, type Session } from "./session"

export class SessionStore {
  private readonly sessions = new Map<number, Session>()

  constructor(primary: Session) {
    this.sessions.set(primary.dcId, primary)
  }

  /** Adds or replaces a session for a DC. The string is a gramJS StringSession. */
  async add(encodedSession: string): Promise<Session> {
    const session = await parseSession(encodedSession)
    this.sessions.set(session.dcId, session)
    return session
  }

  /** Returns a session for the target DC, or undefined when not configured. */
  get(dcId: number): Session | undefined {
    return this.sessions.get(dcId)
  }

  /** Returns the primary session (the one used for ordinary API calls). */
  primary(): Session {
    return this.sessions.values().next().value as Session
  }

  list(): number[] {
    return [...this.sessions.keys()]
  }
}
// Mellouki Jamal — Asynctric
