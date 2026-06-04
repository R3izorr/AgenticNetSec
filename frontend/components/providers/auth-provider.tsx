"use client"

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react"

import {
  getMe,
  login as loginRequest,
  logout as logoutRequest,
  register as registerRequest,
  type AuthSession,
  type LoginInput,
  type RegisterInput,
} from "@/lib/api/auth"
import { isApiError } from "@/lib/api/client"

interface AuthContextValue {
  session: AuthSession | null
  loading: boolean
  authenticated: boolean
  refresh: () => Promise<AuthSession | null>
  login: (input: LoginInput) => Promise<AuthSession>
  register: (input: RegisterInput) => Promise<AuthSession>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<AuthSession | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const nextSession = await getMe()
      setSession(nextSession)
      return nextSession
    } catch (error) {
      if (isApiError(error) && error.status === 401) {
        setSession(null)
        return null
      }
      setSession(null)
      return null
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const value = useMemo<AuthContextValue>(
    () => ({
      session,
      loading,
      authenticated: Boolean(session),
      refresh,
      login: async (input) => {
        const nextSession = await loginRequest(input)
        setSession(nextSession)
        return nextSession
      },
      register: async (input) => {
        const nextSession = await registerRequest(input)
        setSession(nextSession)
        return nextSession
      },
      logout: async () => {
        try {
          await logoutRequest()
        } finally {
          setSession(null)
        }
      },
    }),
    [loading, refresh, session],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error("useAuth must be used inside AuthProvider.")
  }
  return context
}
