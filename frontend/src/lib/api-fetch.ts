/**
 * Authenticated fetch wrapper for SentinelIQ API requests.
 *
 * Gets the current Supabase session and attaches:
 *
 * Authorization: Bearer <access_token>
 *
 * Protected API requests are never silently retried without authentication.
 */

import { supabase } from "@/lib/supabase"

export async function apiFetch(
  url: string,
  init: RequestInit = {}
): Promise<Response> {
  const {
    data: { session },
    error,
  } = await supabase.auth.getSession()

  if (error) {
    throw new Error(
      `Authentication error: ${error.message}`
    )
  }

  if (!session?.access_token) {
    throw new Error(
      "No active Supabase session. Please sign in again."
    )
  }

  const headers = new Headers(init.headers)

  headers.set(
    "Authorization",
    `Bearer ${session.access_token}`
  )

  return fetch(url, {
    ...init,
    headers,
  })
}
