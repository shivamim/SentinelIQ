"use client"

import { createBrowserClient, type Session } from "@supabase/ssr"
import { useRouter } from "next/navigation"
import { createContext, useContext, useEffect, useState, useCallback } from "react"

const supabase = createBrowserClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
)

type User = {
  id: string
  email: string
  role: string
} | null

const AuthContext = createContext<{ user: User; loading: boolean; refreshUser: () => Promise<void> }>({
  user: null,
  loading: true,
  refreshUser: async () => {},
})

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User>(null)
  const [loading, setLoading] = useState(true)
  const router = useRouter()

  // Function to fetch local user profile from backend
  const fetchUserProfile = useCallback(async (accessToken: string): Promise<User | null> => {
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/me`, {
        headers: { 
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      })
      if (res.ok) {
        const profile = await res.json()
        return { id: profile.id, email: profile.email, role: profile.role }
      }
      return null
    } catch {
      return null
    }
  }, [])

  // Initialize session on mount
  useEffect(() => {
    let mounted = true

    const initAuth = async () => {
      try {
        // Get existing session first
        const { data: { session } } = await supabase.auth.getSession()
        
        if (mounted && session?.user) {
          // Fetch local user profile with role
          const profile = await fetchUserProfile(session.access_token)
          if (mounted) {
            if (profile) {
              setUser(profile)
            } else {
              // Fallback: use Supabase user info without role
              setUser({ 
                id: session.user.id, 
                email: session.user.email ?? "", 
                role: "analyst" 
              })
            }
          }
        } else if (mounted) {
          setUser(null)
        }
      } catch (error) {
        console.error("Auth initialization error:", error)
        if (mounted) {
          setUser(null)
        }
      } finally {
        if (mounted) {
          setLoading(false)
        }
      }
    }

    initAuth()

    // Subscribe to auth state changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange(async (event, session) => {
      if (session?.user) {
        // Fetch local user profile with role
        const profile = await fetchUserProfile(session.access_token)
        if (profile) {
          setUser(profile)
        } else {
          setUser({ 
            id: session.user.id, 
            email: session.user.email ?? "", 
            role: "analyst" 
          })
        }
      } else {
        setUser(null)
      }
      setLoading(false)
    })

    return () => {
      mounted = false
      subscription.unsubscribe()
    }
  }, [fetchUserProfile])

  const refreshUser = useCallback(async () => {
    const { data: { session } } = await supabase.auth.getSession()
    if (session?.user) {
      const profile = await fetchUserProfile(session.access_token)
      if (profile) {
        setUser(profile)
      }
    }
  }, [fetchUserProfile])

  return (
    <AuthContext.Provider value={{ user, loading, refreshUser }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
export { supabase }
