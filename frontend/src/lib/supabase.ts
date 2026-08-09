/**
 * Supabase client for browser-side authentication.
 *
 * Provides:
 * - Shared `supabase` browser client for the application
 * - Backwards-compatible `createClient()` export
 */

import { createBrowserClient } from "@supabase/ssr"

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
const supabaseAnonKey =
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

if (!supabaseUrl) {
  throw new Error(
    "Missing NEXT_PUBLIC_SUPABASE_URL environment variable"
  )
}

if (!supabaseAnonKey) {
  throw new Error(
    "Missing NEXT_PUBLIC_SUPABASE_ANON_KEY environment variable"
  )
}

/**
 * Single shared browser client.
 */
export const supabase = createBrowserClient(
  supabaseUrl,
  supabaseAnonKey
)

/**
 * Backwards-compatible export.
 *
 * Existing pages that still use:
 *
 *     const supabase = createClient()
 *
 * will continue to work.
 */
export function createClient() {
  return supabase
}
