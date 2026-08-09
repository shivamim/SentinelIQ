/** Fetch wrapper that adds auth token from Supabase session. */

// Module-level cache for the Supabase client to avoid circular imports
let _supabase: any = null

async function getSupabase() {
  if (!_supabase) {
    const { supabase } = await import("@/components/auth-provider")
    _supabase = supabase
  }
  return _supabase
}

export async function apiFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const supabase = await getSupabase()
  
  // Always get fresh session to ensure we have a valid token
  const { data: { session }, error: sessionError } = await supabase.auth.getSession()
  
  if (sessionError) {
    console.error("Failed to get Supabase session:", sessionError)
    throw new Error("No active Supabase session. Please sign in again.")
  }
  
  if (!session?.access_token) {
    throw new Error("No active Supabase session. Please sign in again.")
  }
  
  const headers: Record<string, string> = {
    ...(init.headers as Record<string, string> || {}),
  }
  
  // Always attach Authorization header for authenticated requests
  headers["Authorization"] = `Bearer ${session.access_token}`
  
  // Ensure Content-Type is set for JSON requests if body is present
  if (init.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json"
  }
  
  try {
    const response = await fetch(url, { ...init, headers })
    return response
  } catch (error) {
    // Re-throw network errors with clear message
    throw new Error(`Network error: ${error instanceof Error ? error.message : 'Failed to fetch'}`)
  }
}
