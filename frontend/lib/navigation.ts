export function resolveSafeNextPath(value: string | null | undefined, fallback = "/dashboard"): string {
  if (!value) {
    return fallback
  }

  if (!value.startsWith("/") || value.startsWith("//")) {
    return fallback
  }

  try {
    const parsed = new URL(value, "http://agenticnetsec.local")
    if (parsed.origin !== "http://agenticnetsec.local") {
      return fallback
    }
    return `${parsed.pathname}${parsed.search}${parsed.hash}` || fallback
  } catch {
    return fallback
  }
}
