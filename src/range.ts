export interface RangeSpec {
  start: number
  end: number
  partial: boolean
}

export function parseRange(header: string | null, size: number): RangeSpec | null {
  if (!header) return { start: 0, end: size - 1, partial: false }
  const match = /^bytes=(\d*)-(\d*)$/.exec(header.trim())
  if (!match) return null
  if (match[1] === "" && match[2] === "") return null
  let start: number
  let end: number
  if (match[1] === "") {
    const suffix = Number(match[2])
    if (!Number.isFinite(suffix) || suffix <= 0) return null
    start = Math.max(0, size - suffix)
    end = size - 1
  } else {
    start = Number(match[1])
    end = match[2] === "" ? size - 1 : Number(match[2])
    if (!Number.isFinite(start) || !Number.isFinite(end)) return null
  }
  if (start < 0 || end < start || start >= size) return null
  return { start, end: Math.min(end, size - 1), partial: true }
}
// Made By MELLOUKI JAMAL
