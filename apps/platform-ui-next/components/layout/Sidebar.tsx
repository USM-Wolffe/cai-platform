"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { LayoutDashboard, Shield, Mail, FolderOpen } from "lucide-react";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/watchguard", label: "WatchGuard", icon: Shield },
  { href: "/phishing", label: "Phishing", icon: Mail },
];

interface SidebarProps {
  onCasesClick: () => void;
}

export function Sidebar({ onCasesClick }: SidebarProps) {
  const pathname = usePathname();

  return (
    <nav className="flex h-full w-14 flex-col items-center gap-1 border-r border-border bg-sidebar py-4">
      {/* Logo */}
      <div className="mb-4 flex size-8 items-center justify-center rounded-lg bg-primary">
        <span className="text-xs font-bold text-primary-foreground">C</span>
      </div>

      {/* Nav links */}
      <div className="flex flex-1 flex-col items-center gap-1">
        {NAV.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + "/");
          return (
            <Link
              key={href}
              href={href}
              title={label}
              className={cn(
                "flex size-9 items-center justify-center rounded-lg transition-colors",
                active
                  ? "bg-primary/15 text-primary"
                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
              )}
            >
              <Icon className="size-4" />
            </Link>
          );
        })}
      </div>

      {/* Cases button */}
      <button
        onClick={onCasesClick}
        title="Case History"
        className="flex size-9 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
      >
        <FolderOpen className="size-4" />
      </button>
    </nav>
  );
}
