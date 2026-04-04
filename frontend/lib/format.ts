export function formatPercent(value: number): string {
  const clamped = Math.max(0, Math.min(1, value))
  return `${Math.round(clamped * 100)}%`
}

export function formatDateTime(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return date.toLocaleString()
}

export function formatNumber(value: number, fractionDigits = 2): string {
  if (!Number.isFinite(value)) {
    return "0"
  }
  return value.toLocaleString(undefined, {
    minimumFractionDigits: 0,
    maximumFractionDigits: fractionDigits,
  })
}

export function formatBytes(value: number | null | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return "N/A"
  }
  if (value < 1024) {
    return `${formatNumber(value, 0)} B`
  }
  const units = ["KB", "MB", "GB", "TB"]
  let size = value / 1024
  let unitIndex = 0
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024
    unitIndex += 1
  }
  return `${formatNumber(size, size >= 10 ? 1 : 2)} ${units[unitIndex]}`
}

export function formatPhaseLabel(phase: string): string {
  if (!phase) {
    return "Unknown"
  }
  const value = phase.replace(/[_-]+/g, " ")
  if (value.toLowerCase() === "analysis") {
    return "Detect / Analyze"
  }
  return titleCase(value)
}

export function titleCase(input: string): string {
  return input
    .replace(/[_-]+/g, " ")
    .split(" ")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ")
}
