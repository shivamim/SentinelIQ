/** Fetch wrapper that adds auth token from Supabase session. */
export async function apiFetch(url: string, init: RequestInit = {}): Promise<Response> {
  try {
    const { supabase } = await import("@/components/auth-provider")
    const { data: { session } } = await supabase.auth.getSession()
    const token = session?.access_token || ""

    const headers: Record<string, string> = {
      ...(init.headers as Record<string, string> || {}),
    }
    if (token) {
      headers["Authorization"] = `Bearer ${token}`
    }

    return fetch(url, { ...init, headers })
  } catch {
    return fetch(url, init)
  }
}
