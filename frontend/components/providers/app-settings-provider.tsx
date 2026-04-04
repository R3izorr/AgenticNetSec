"use client"

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useSyncExternalStore,
  type ReactNode,
} from "react"
import {
  type AppSettings,
  getSettingsSnapshot,
  resolvePollIntervalMs,
  resolveThemeClass,
  resetSettingsSnapshot,
  subscribeToSettings,
  updateSettingsSnapshot,
} from "@/lib/settings"

interface AppSettingsContextValue {
  settings: AppSettings
  resolvedPollIntervalMs: number
  updateSettings: (nextSettings: AppSettings) => void
  resetSettings: () => void
}

const AppSettingsContext = createContext<AppSettingsContextValue | null>(null)

function applyTheme(theme: AppSettings["theme"]) {
  if (typeof document === "undefined") {
    return
  }

  const root = document.documentElement
  const resolvedTheme = resolveThemeClass(theme)
  root.classList.remove("dark", "light")
  root.classList.add(resolvedTheme)
}

export function AppSettingsProvider({ children }: { children: ReactNode }) {
  const settings = useSyncExternalStore(
    subscribeToSettings,
    getSettingsSnapshot,
    getSettingsSnapshot
  )

  useEffect(() => {
    applyTheme(settings.theme)
  }, [settings.theme])

  useEffect(() => {
    if (typeof window === "undefined" || settings.theme !== "system") {
      return
    }

    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)")
    const handleChange = () => applyTheme("system")
    mediaQuery.addEventListener("change", handleChange)
    return () => mediaQuery.removeEventListener("change", handleChange)
  }, [settings.theme])

  const updateSettings = useCallback((nextSettings: AppSettings) => {
    updateSettingsSnapshot(nextSettings)
  }, [])

  const resetSettings = useCallback(() => {
    resetSettingsSnapshot()
    applyTheme("dark")
  }, [])

  const value = useMemo<AppSettingsContextValue>(
    () => ({
      settings,
      resolvedPollIntervalMs: resolvePollIntervalMs(settings),
      updateSettings,
      resetSettings,
    }),
    [settings, updateSettings, resetSettings]
  )

  return <AppSettingsContext.Provider value={value}>{children}</AppSettingsContext.Provider>
}

export function useAppSettings() {
  const context = useContext(AppSettingsContext)
  if (!context) {
    throw new Error("useAppSettings must be used within AppSettingsProvider")
  }
  return context
}
