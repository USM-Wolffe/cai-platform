"use client";

import { useState } from "react";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { CasesSheet } from "./CasesSheet";
import { AIPanel } from "./AIPanel";

interface AppShellProps {
  children: ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  const [casesOpen, setCasesOpen] = useState(false);
  const pathname = usePathname();

  // Build AI context from current path
  const page = pathname.split("/").filter(Boolean).at(-1) ?? "dashboard";

  return (
    <div className="flex h-full">
      <Sidebar onCasesClick={() => setCasesOpen(true)} />
      <main className="flex flex-1 flex-col overflow-auto">{children}</main>
      <CasesSheet open={casesOpen} onClose={() => setCasesOpen(false)} />
      <AIPanel context={{ page }} />
    </div>
  );
}
