"use client"

import { useRouter } from "next/navigation"
import {
  createContext,
  useContext,
  useEffect,
  useState,
} from "react"

import { supabase } from "@/lib/supabase"

type User = {
  id: string
  email: string
  role: string
} | null

type AuthContextType = {
  user: User
  loading: boolean
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
})

export function AuthProvider({
  children,
}: {
  children: React.ReactNode
}) {
  const [user, setUser] = useState<User>(null)
  const [loading, setLoading] = useState(true)

  const router = useRouter()

  useEffect(() => {
    let mounted = true

    /**
     * Load the current Supabase session when the application starts.
     */
    const loadSession = async () => {
      try {
        const {
          data: { session },
          error,
        } = await supabase.auth.getSession()

        if (error) {
          console.error(
            "Failed to get Supabase session:",
            error.message
          )

          if (mounted) {
            setUser(null)
            setLoading(false)
          }

          return
        }

        if (!session?.user) {
          if (mounted) {
            setUser(null)
            setLoading(false)
          }

          return
        }

        await loadLocalUser(session.access_token, session.user)
      } catch (error) {
        console.error(
          "Session initialization failed:",
          error
        )

        if (mounted) {
          setUser(null)
          setLoading(false)
        }
      }
    }

    /**
     * Load the corresponding local SentinelIQ user.
     */
    const loadLocalUser = async (
      accessToken: string,
      supabaseUser: {
        id: string
        email?: string
      }
    ) => {
      try {
        const apiUrl = process.env.NEXT_PUBLIC_API_URL

        if (!apiUrl) {
          throw new Error(
            "NEXT_PUBLIC_API_URL is not configured"
          )
        }

        const response = await fetch(
          `${apiUrl}/auth/me`,
          {
            method: "GET",
            headers: {
              Authorization: `Bearer ${accessToken}`,
              Accept: "application/json",
            },
          }
        )

        if (!mounted) {
          return
        }

        if (response.ok) {
          const profile = await response.json()

          setUser({
            id: profile.id,
            email: profile.email,
            role: profile.role,
          })
        } else if (response.status === 401) {
          console.warn(
            "Supabase session exists but backend rejected the token."
          )

          setUser({
            id: supabaseUser.id,
            email: supabaseUser.email ?? "",
            role: "analyst",
          })
        } else {
          console.error(
            `Backend /auth/me returned ${response.status}`
          )

          setUser({
            id: supabaseUser.id,
            email: supabaseUser.email ?? "",
            role: "analyst",
          })
        }
      } catch (error) {
        console.error(
          "Failed to load local SentinelIQ user:",
          error
        )

        if (mounted) {
          setUser({
            id: supabaseUser.id,
            email: supabaseUser.email ?? "",
            role: "analyst",
          })
        }
      } finally {
        if (mounted) {
          setLoading(false)
        }
      }
    }

    /**
     * Initialize existing session first.
     */
    loadSession()

    /**
     * Listen for login/logout/session refresh events.
     */
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange(
      async (_event, session) => {
        if (!mounted) {
          return
        }

        if (!session?.user) {
          setUser(null)
          setLoading(false)
          return
        }

        setLoading(true)

        await loadLocalUser(
          session.access_token,
          session.user
        )
      }
    )

    return () => {
      mounted = false
      subscription.unsubscribe()
    }
  }, [])

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)

// Export the shared Supabase client for existing imports
// elsewhere in the application.
export { supabase }
