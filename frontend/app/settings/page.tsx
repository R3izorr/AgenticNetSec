"use client"

import { useMemo, useState } from "react"
import { InlineNotice } from "@/components/common/inline-notice"
import { KeyValueGrid } from "@/components/common/key-value-grid"
import { SectionCard } from "@/components/common/section-card"
import { StatusBadge } from "@/components/common/status-badge"
import { useAuth } from "@/components/providers/auth-provider"
import { useAppSettings } from "@/components/providers/app-settings-provider"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { useToast } from "@/components/ui/toast"
import {
  DEFAULT_APP_SETTINGS,
  DEFAULT_POLL_INTERVAL_MS,
  getDefaultApiBaseUrl,
  resolveApiBaseUrl,
  resolvePollIntervalMs,
  type AppSettings,
  type ThemePreference,
} from "@/lib/settings"

const POLL_OPTIONS = [1000, 3000, 5000, 10000, 15000]

function normalizeApiBaseUrlInput(value: string): string | null {
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

function buildDraftFromSettings(settings: AppSettings) {
  const nextPollInterval = resolvePollIntervalMs(settings)
  return {
    apiBaseUrlInput: settings.apiBaseUrlOverride ?? "",
    pollIntervalInput: POLL_OPTIONS.includes(nextPollInterval) ? String(nextPollInterval) : String(DEFAULT_POLL_INTERVAL_MS),
    theme: settings.theme,
  }
}

function AccountWorkspacePanel() {
  const { session, refresh } = useAuth()

  return (
    <SectionCard
      title="Account"
      subtitle="Current authenticated user and organization context."
      actions={
        <Button type="button" variant="outline" size="sm" onClick={() => void refresh()}>
          Refresh Session
        </Button>
      }
    >
      <KeyValueGrid
        items={[
          { label: "Email", value: session?.user.email ?? "N/A" },
          { label: "Display Name", value: session?.user.display_name || "Not set" },
          { label: "User ID", value: <code className="text-xs">{session?.user.id ?? "N/A"}</code> },
          { label: "Organization", value: session?.organization.name ?? "N/A" },
          { label: "Organization Slug", value: session?.organization.slug ?? "N/A" },
          { label: "Organization ID", value: <code className="text-xs">{session?.organization.id ?? "N/A"}</code> },
          { label: "Role", value: <StatusBadge value={session?.organization.role ?? "unknown"} /> },
        ]}
      />
    </SectionCard>
  )
}

function SettingsForm({
  settings,
  onSave,
  onResetAll,
}: {
  settings: AppSettings
  onSave: (nextSettings: AppSettings, message: string) => void
  onResetAll: () => void
}) {
  const draft = buildDraftFromSettings(settings)
  const [apiBaseUrlInput, setApiBaseUrlInput] = useState(draft.apiBaseUrlInput)
  const [pollIntervalInput, setPollIntervalInput] = useState(draft.pollIntervalInput)
  const [theme, setTheme] = useState<ThemePreference>(draft.theme)
  const [formError, setFormError] = useState<string | null>(null)

  const resolvedApiBaseUrl = useMemo(() => resolveApiBaseUrl(settings), [settings])
  const resolvedPollInterval = useMemo(() => resolvePollIntervalMs(settings), [settings])
  const defaultApiBaseUrl = getDefaultApiBaseUrl()
  const usingCustomApiBaseUrl = resolvedApiBaseUrl !== defaultApiBaseUrl

  function applySettings(nextSettings: AppSettings, successMessage: string) {
    onSave(nextSettings, successMessage)
    setFormError(null)
  }

  function onSaveAll() {
    const normalizedApiBaseUrl = normalizeApiBaseUrlInput(apiBaseUrlInput)
    if (apiBaseUrlInput.trim() && !normalizedApiBaseUrl) {
      setFormError("Enter a valid API base URL including http:// or https://.")
      return
    }

    const parsedPollInterval = Number(pollIntervalInput)
    if (!POLL_OPTIONS.includes(parsedPollInterval)) {
      setFormError("Choose one of the supported polling intervals.")
      return
    }

    applySettings(
      {
        apiBaseUrlOverride: normalizedApiBaseUrl,
        pollIntervalMs: parsedPollInterval,
        theme,
      },
      "Your browser-local preferences have been updated."
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <AccountWorkspacePanel />

      <SectionCard
        title="Settings"
        subtitle="Manage browser-local runtime preferences for the frontend."
        actions={
          <Button type="button" variant="outline" size="sm" onClick={onResetAll}>
            Reset All
          </Button>
        }
      >
        <div className="flex flex-col gap-4">
          <InlineNotice title="Local only">
            These preferences are stored in this browser only. They do not change backend configuration and they are not shared with other machines or users.
          </InlineNotice>
          {usingCustomApiBaseUrl ? (
            <InlineNotice variant="warning" title="Custom API origin">
              Requests use credentials for the configured API origin. Keep this set to a trusted local backend.
            </InlineNotice>
          ) : null}
          {formError ? <InlineNotice variant="error">{formError}</InlineNotice> : null}
        </div>
      </SectionCard>

      <SectionCard
        title="Connectivity"
        subtitle="Override the backend API origin used by all frontend requests."
        actions={
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => applySettings({ ...settings, apiBaseUrlOverride: null }, "API base URL reset to the default backend endpoint.")}
          >
            Reset Default
          </Button>
        }
      >
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2">
            <Label htmlFor="api-base-url">API base URL</Label>
            <Input
              id="api-base-url"
              value={apiBaseUrlInput}
              onChange={(event) => setApiBaseUrlInput(event.target.value)}
              placeholder={defaultApiBaseUrl}
              className="bg-card"
              aria-invalid={Boolean(formError && apiBaseUrlInput.trim() && !normalizeApiBaseUrlInput(apiBaseUrlInput))}
            />
            <p className="text-sm text-muted-foreground">
              Leave blank to use the default value from the app environment.
            </p>
          </div>
          <Separator />
          <div className="flex flex-col gap-1 text-sm">
            <span className="text-muted-foreground">Resolved value</span>
            <code className="rounded-md border border-border/70 bg-background/40 px-3 py-2">{resolvedApiBaseUrl}</code>
          </div>
        </div>
      </SectionCard>

      <SectionCard
        title="Polling"
        subtitle="Control how often status and artifact pages refresh while work is in progress."
        actions={
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => applySettings({ ...settings, pollIntervalMs: null }, "Polling interval reset to the default cadence.")}
          >
            Reset Default
          </Button>
        }
      >
        <div className="flex flex-col gap-4 md:max-w-sm">
          <div className="flex flex-col gap-2">
            <Label htmlFor="poll-interval">Polling interval</Label>
            <Select value={pollIntervalInput} onValueChange={setPollIntervalInput}>
              <SelectTrigger id="poll-interval" className="bg-card">
                <SelectValue placeholder="Select interval" />
              </SelectTrigger>
              <SelectContent>
                {POLL_OPTIONS.map((value) => (
                  <SelectItem key={value} value={String(value)}>
                    {value} ms
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-sm text-muted-foreground">
              This value applies globally to job status polling and artifact retry polling.
            </p>
          </div>
          <Separator />
          <div className="flex flex-col gap-1 text-sm">
            <span className="text-muted-foreground">Resolved value</span>
            <code className="rounded-md border border-border/70 bg-background/40 px-3 py-2">{resolvedPollInterval} ms</code>
          </div>
        </div>
      </SectionCard>

      <SectionCard
        title="Appearance"
        subtitle="Choose how the frontend theme is applied in this browser."
        actions={
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => applySettings({ ...settings, theme: DEFAULT_APP_SETTINGS.theme }, "Theme preference reset to the default analyst theme.")}
          >
            Reset Default
          </Button>
        }
      >
        <div className="flex flex-col gap-4 md:max-w-sm">
          <div className="flex flex-col gap-2">
            <Label htmlFor="theme-preference">Theme</Label>
            <Select value={theme} onValueChange={(value) => setTheme(value as ThemePreference)}>
              <SelectTrigger id="theme-preference" className="bg-card">
                <SelectValue placeholder="Select theme" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="dark">Dark</SelectItem>
                <SelectItem value="light">Light</SelectItem>
                <SelectItem value="system">System</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-sm text-muted-foreground">
              Default remains dark to preserve the current analyst dashboard presentation.
            </p>
          </div>
        </div>
      </SectionCard>

      <div className="flex items-center gap-3">
        <Button type="button" onClick={onSaveAll}>Save Changes</Button>
        <p className="text-sm text-muted-foreground">Settings apply to this browser immediately after saving.</p>
      </div>
    </div>
  )
}

export default function SettingsPage() {
  const { pushToast } = useToast()
  const { settings, updateSettings, resetSettings } = useAppSettings()

  function handleSave(nextSettings: AppSettings, message: string) {
    updateSettings(nextSettings)
    pushToast({
      variant: "success",
      title: "Settings saved",
      description: message,
    })
  }

  function handleResetAll() {
    resetSettings()
    pushToast({
      variant: "success",
      title: "Settings reset",
      description: "All browser-local preferences were restored to defaults.",
    })
  }

  const settingsKey = JSON.stringify(settings)

  return <SettingsForm key={settingsKey} settings={settings} onSave={handleSave} onResetAll={handleResetAll} />
}
