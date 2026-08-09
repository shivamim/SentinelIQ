/** API client for SentinelIQ backend. */
import { apiFetch } from "./api-fetch"

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

export const api = {
  async get<T>(path: string): Promise<T> {
    const res = await apiFetch(`${API_BASE}${path}`, { method: "GET" })
    
    if (!res.ok) {
      if (res.status === 401) {
        throw new Error("Session expired. Please sign in again.")
      }
      if (res.status === 403) {
        throw new Error("Insufficient permissions for this action.")
      }
      const errText = await res.text().catch(() => "")
      throw new Error(`API error: ${res.status} ${errText}`)
    }
    
    return res.json()
  },

  async post<T>(path: string, body: unknown): Promise<T> {
    const res = await apiFetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
    
    if (!res.ok) {
      if (res.status === 401) {
        throw new Error("Session expired. Please sign in again.")
      }
      if (res.status === 403) {
        throw new Error("Insufficient permissions for this action.")
      }
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || `API error: ${res.status}`)
    }
    
    return res.json()
  },

  async delete<T>(path: string): Promise<T> {
    const res = await apiFetch(`${API_BASE}${path}`, { method: "DELETE" })
    
    if (!res.ok) {
      if (res.status === 401) {
        throw new Error("Session expired. Please sign in again.")
      }
      if (res.status === 403) {
        throw new Error("Insufficient permissions for this action.")
      }
      throw new Error(`API error: ${res.status}`)
    }
    
    return res.json()
  },
}

export { apiFetch }
