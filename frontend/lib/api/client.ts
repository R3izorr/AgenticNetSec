import { getConfiguredApiBaseUrl, getDefaultApiBaseUrl } from "@/lib/settings"

export type ApiErrorCode =
  | "unauthorized"
  | "forbidden"
  | "bad_request"
  | "not_found"
  | "not_ready"
  | "server_error"
  | "network_error"
  | "unknown"

export class ApiError extends Error {
  status: number
  code: ApiErrorCode
  detail: string

  constructor(message: string, status: number, code: ApiErrorCode, detail = "") {
    super(message)
    this.name = "ApiError"
    this.status = status
    this.code = code
    this.detail = detail
  }
}

function getBaseUrl(): string {
  if (typeof window !== "undefined") {
    return getConfiguredApiBaseUrl()
  }

  return getDefaultApiBaseUrl()
}

function buildUrl(path: string): string {
  const base = getBaseUrl().replace(/\/$/, "")
  const normalizedPath = path.startsWith("/") ? path : `/${path}`
  return `${base}${normalizedPath}`
}

function toApiError(status: number, detail: string): ApiError {
  if (status === 400) {
    return new ApiError("Bad request.", status, "bad_request", detail)
  }
  if (status === 401) {
    return new ApiError("Not authenticated.", status, "unauthorized", detail)
  }
  if (status === 403) {
    return new ApiError("Insufficient permissions.", status, "forbidden", detail)
  }
  if (status === 404) {
    return new ApiError("Resource not found.", status, "not_found", detail)
  }
  if (status === 409) {
    return new ApiError("Artifact not ready.", status, "not_ready", detail)
  }
  if (status >= 500) {
    return new ApiError("Server error.", status, "server_error", detail)
  }
  return new ApiError("Request failed.", status, "unknown", detail)
}

async function parseErrorDetail(response: Response): Promise<string> {
  try {
    const data: unknown = await response.json()
    if (typeof data === "object" && data && "detail" in data) {
      const detail = data.detail
      if (typeof detail === "string") {
        return detail
      }
    }
  } catch {
    // Ignore JSON parse failures and fallback below.
  }

  try {
    return await response.text()
  } catch {
    return ""
  }
}

export async function apiRequest<T>(
  path: string,
  init?: RequestInit
): Promise<T> {
  const url = buildUrl(path)

  let response: Response
  try {
    response = await fetch(url, {
      ...init,
      credentials: init?.credentials ?? "include",
    })
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Network request failed."
    throw new ApiError(message, 0, "network_error", message)
  }

  if (!response.ok) {
    const detail = await parseErrorDetail(response)
    throw toApiError(response.status, detail)
  }

  if (response.status === 204) {
    return undefined as T
  }
  return (await response.json()) as T
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError
}
