/**
 * API client for SentinelIQ backend.
 */

import { apiFetch } from "./api-fetch"

const API_BASE = process.env.NEXT_PUBLIC_API_URL

if (!API_BASE) {
  throw new Error(
    "Missing NEXT_PUBLIC_API_URL environment variable"
  )
}

export const api = {
  async get<T = any>(path: string): Promise<T> {
    const res = await apiFetch(
      `${API_BASE}${path}`,
      {
        method: "GET",
      }
    )

    if (!res.ok) {
      const err = await res
        .json()
        .catch(() => ({
          detail: res.statusText,
        }))

      throw new Error(
        err.detail || `API error: ${res.status}`
      )
    }

    return res.json() as Promise<T>
  },

  async post<T = any>(
    path: string,
    body: unknown
  ): Promise<T> {
    const res = await apiFetch(
      `${API_BASE}${path}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      }
    )

    if (!res.ok) {
      const err = await res
        .json()
        .catch(() => ({
          detail: res.statusText,
        }))

      throw new Error(
        err.detail || `API error: ${res.status}`
      )
    }

    return res.json() as Promise<T>
  },

  async delete<T = any>(path: string): Promise<T> {
    const res = await apiFetch(
      `${API_BASE}${path}`,
      {
        method: "DELETE",
      }
    )

    if (!res.ok) {
      const err = await res
        .json()
        .catch(() => ({
          detail: res.statusText,
        }))

      throw new Error(
        err.detail || `API error: ${res.status}`
      )
    }

    return res.json() as Promise<T>
  },
}

export { apiFetch }
