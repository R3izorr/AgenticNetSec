export const DEFAULT_API_BASE_URL = "http://localhost:8000"
export const DEFAULT_POLL_INTERVAL_MS = 3000
export const SETTINGS_STORAGE_KEY = "agenticnetsec.settings.v1"

export type ThemePreference = "dark" | "light" | "system"

export interface AppSettings {
  apiBaseUrlOverride: string | null
  pollIntervalMs: number | null
  theme: ThemePreference
}

export const DEFAULT_APP_SETTINGS: AppSettings = {
  apiBaseUrlOverride: null,
  pollIntervalMs: null,
  theme: "dark",
}

let settingsSnapshot: AppSettings = DEFAULT_APP_SETTINGS
let settingsInitialized = false
const settingsListeners = new Set<() => void>()

function isThemePreference(value: unknown): value is ThemePreference {
  return value === "dark" || value === "light" || value === "system"
}

function normalizeApiBaseUrl(value: unknown): string | null {
  if (typeof value !== "string") {
    return null
  }

  const trimmed = value.trim()
  if (!trimmed) {
    return null
  }

  try {
    const parsed = new URL(trimmed)
    return parsed.toString().replace(/\/$/, "")
  } catch {
    return null
  }
}

function normalizePollInterval(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null
  }

  const rounded = Math.round(value)
  if (rounded < 1000 || rounded > 60000) {
    return null
  }

  return rounded
}

export function getDefaultApiBaseUrl(): string {
  return process.env.NEXT_PUBLIC_API_BASE_URL ?? DEFAULT_API_BASE_URL
}

export function sanitizeSettings(value: unknown): AppSettings {
  if (typeof value !== "object" || value === null) {
    return DEFAULT_APP_SETTINGS
  }

  const candidate = value as Record<string, unknown>

  return {
    apiBaseUrlOverride: normalizeApiBaseUrl(candidate.apiBaseUrlOverride),
    pollIntervalMs: normalizePollInterval(candidate.pollIntervalMs),
    theme: isThemePreference(candidate.theme) ? candidate.theme : DEFAULT_APP_SETTINGS.theme,
  }
}

export function readStoredSettings(): AppSettings {
  if (typeof window === "undefined") {
    return DEFAULT_APP_SETTINGS
  }

  try {
    const rawValue = window.localStorage.getItem(SETTINGS_STORAGE_KEY)
    if (!rawValue) {
      return DEFAULT_APP_SETTINGS
    }

    return sanitizeSettings(JSON.parse(rawValue))
  } catch {
    return DEFAULT_APP_SETTINGS
  }
}

export function writeStoredSettings(settings: AppSettings): void {
  if (typeof window === "undefined") {
    return
  }

  window.localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings))
}

export function clearStoredSettings(): void {
  if (typeof window === "undefined") {
    return
  }

  window.localStorage.removeItem(SETTINGS_STORAGE_KEY)
}

export function resolveApiBaseUrl(settings: AppSettings): string {
  return settings.apiBaseUrlOverride ?? getDefaultApiBaseUrl()
}

export function resolvePollIntervalMs(settings: AppSettings): number {
  return settings.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS
}

export function resolveThemeClass(theme: ThemePreference): "dark" | "light" {
  if (theme === "system") {
    if (
      typeof window !== "undefined" &&
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches
    ) {
      return "dark"
    }
    return "light"
  }

  return theme
}

function initializeSettingsStore(): void {
  if (settingsInitialized) {
    return
  }

  settingsSnapshot = readStoredSettings()
  settingsInitialized = true
}

function emitSettingsChange(): void {
  for (const listener of settingsListeners) {
    listener()
  }
}

export function getSettingsSnapshot(): AppSettings {
  if (typeof window !== "undefined") {
    initializeSettingsStore()
  }
  return settingsSnapshot
}

export function subscribeToSettings(listener: () => void): () => void {
  settingsListeners.add(listener)
  return () => {
    settingsListeners.delete(listener)
  }
}

export function updateSettingsSnapshot(settings: AppSettings): void {
  settingsSnapshot = settings
  settingsInitialized = true
  writeStoredSettings(settings)
  emitSettingsChange()
}

export function resetSettingsSnapshot(): void {
  settingsSnapshot = DEFAULT_APP_SETTINGS
  settingsInitialized = true
  clearStoredSettings()
  emitSettingsChange()
}

export function getConfiguredApiBaseUrl(): string {
  return resolveApiBaseUrl(getSettingsSnapshot())
}
