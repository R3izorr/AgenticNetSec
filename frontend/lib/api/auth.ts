import { apiRequest } from "@/lib/api/client"

export interface AuthUser {
  id: string
  email: string
  display_name: string | null
}

export interface AuthOrganization {
  id: string
  name: string
  slug: string
  role: string
}

export interface AuthSession {
  user: AuthUser
  organization: AuthOrganization
}

export interface RegisterInput {
  email: string
  password: string
  displayName?: string
}

export interface LoginInput {
  email: string
  password: string
}

export async function register(input: RegisterInput): Promise<AuthSession> {
  return apiRequest<AuthSession>("/api/v1/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: input.email,
      password: input.password,
      display_name: input.displayName || null,
    }),
  })
}

export async function login(input: LoginInput): Promise<AuthSession> {
  return apiRequest<AuthSession>("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  })
}

export async function logout(): Promise<void> {
  await apiRequest<void>("/api/v1/auth/logout", {
    method: "POST",
  })
}

export async function getMe(): Promise<AuthSession> {
  return apiRequest<AuthSession>("/api/v1/auth/me")
}
