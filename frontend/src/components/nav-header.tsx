"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { Shield } from "lucide-react"
import { cn } from "@/lib/utils"

const NAV_ITEMS = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/alerts", label: "Alerts" },
  { href: "/incidents", label: "Incidents" },
  { href: "/review-queue", label: "Review Queue" },
  { href: "/attack-replay", label: "Attack Replay" },
  { href: "/reports", label: "Reports" },
  { href: "/chat", label: "Chat" },
  { href: "/knowledge", label: "Knowledge" },
]

export function NavHeader({ title }: { title?: string }) {
  const pathname = usePathname()

  return (
    <header className="border-b border-border px-6 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="h-8 w-8 text-primary" />
          <h1 className="text-2xl font-bold">
            {title ? `SentinelIQ — ${title}` : "SentinelIQ"}
          </h1>
        </div>
        <nav className="flex flex-wrap gap-4 text-sm">
          {NAV_ITEMS.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                pathname === item.href
                  ? "text-primary font-medium"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {item.label}
            </Link>
          ))}
        </nav>
      </div>
    </header>
  )
}
