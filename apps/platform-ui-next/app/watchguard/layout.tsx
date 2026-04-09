import { AppShell } from "@/components/layout/AppShell";
import type { ReactNode } from "react";

export default function WatchGuardLayout({ children }: { children: ReactNode }) {
  return <AppShell>{children}</AppShell>;
}
