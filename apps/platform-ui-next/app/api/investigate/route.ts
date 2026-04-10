/**
 * Blue team investigation pipeline orchestrator.
 *
 * Replicates the cai-orchestrator Python pipeline server-side:
 * Phase 1: Create case + 2 artifacts (traffic + alarm) + run
 * Phase 2: Run all 7 multi-source-logs observations
 * Phase 3: Return a structured result (skips AI synthesis — handled by cai-orchestrator if available)
 */

import { NextRequest, NextResponse } from "next/server";

const API = process.env.PLATFORM_API_BASE_URL ?? "http://localhost:8000";

async function call<T>(path: string, method = "GET", body?: unknown): Promise<T> {
  const res = await fetch(`${API}/${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`${method} /${path} → ${res.status}: ${text}`);
  }
  return res.json();
}

export async function POST(req: NextRequest) {
  const { workspace_id, client_id } = await req.json();

  if (!workspace_id || !client_id) {
    return NextResponse.json({ error: "workspace_id and client_id are required" }, { status: 400 });
  }

  try {
    // ── Phase 1: Discover staging prefix ──────────────────────────────────
    let stagingInfo: { staging_prefix: string; bucket: string; region: string };
    try {
      stagingInfo = await call<{ staging_prefix: string; bucket: string; region: string }>(
        `s3/workspaces/${workspace_id}/latest-staging`,
      );
    } catch (e) {
      const msg = e instanceof Error ? e.message : "";
      if (msg.includes("404") || msg.toLowerCase().includes("no staging")) {
        return NextResponse.json(
          { error: `El workspace '${workspace_id}' no tiene datos staged. Usá "Upload new ZIP" para procesarlo primero.` },
          { status: 400 },
        );
      }
      throw e;
    }

    const { staging_prefix, bucket, region } = stagingInfo;

    // ── Phase 1: Create case ──────────────────────────────────────────────
    const { case: newCase } = await call<{ case: { case_id: string } }>("cases", "POST", {
      client_id,
      workflow_type: "log_investigation",
      title: `WatchGuard investigation — ${workspace_id}`,
      summary: `Automated blue team analysis of WatchGuard logs from workspace ${workspace_id}.`,
      metadata: { source: "watchguard", workspace_id },
    });
    const caseId = newCase.case_id;

    // ── Phase 1: Attach traffic artifact ──────────────────────────────────
    const { artifact: trafficArt } = await call<{ artifact: { artifact_id: string } }>(
      `cases/${caseId}/artifacts/input`,
      "POST",
      {
        payload: {
          source_type: "watchguard_traffic",
          staging_prefix,
          bucket,
          region,
        },
      },
    );

    // ── Phase 1: Attach alarm artifact ────────────────────────────────────
    const { artifact: alarmArt } = await call<{ artifact: { artifact_id: string } }>(
      `cases/${caseId}/artifacts/input`,
      "POST",
      {
        payload: {
          source_type: "watchguard_alarm",
          staging_prefix,
          bucket,
          region,
        },
      },
    );

    // ── Phase 1: Create run ───────────────────────────────────────────────
    const { run } = await call<{ run: { run_id: string } }>("runs", "POST", {
      case_id: caseId,
      backend_id: "multi_source_logs",
      input_artifact_ids: [trafficArt.artifact_id, alarmArt.artifact_id],
    });
    const runId = run.run_id;

    const trafficId = trafficArt.artifact_id;
    const alarmId = alarmArt.artifact_id;

    // ── Phase 2: Traffic observations ─────────────────────────────────────
    const [normObs, failedAuthObs, lateralObs, privEscObs, dnsObs] = await Promise.all([
      call<{ artifacts: Array<{ artifact_id: string }> }>(
        `runs/${runId}/observations/multi-source-logs-normalize`,
        "POST",
        { input_artifact_id: trafficId },
      ),
      call<{ artifacts: Array<{ artifact_id: string }> }>(
        `runs/${runId}/observations/multi-source-logs-failed-auth-detect`,
        "POST",
        { input_artifact_id: trafficId },
      ),
      call<{ artifacts: Array<{ artifact_id: string }> }>(
        `runs/${runId}/observations/multi-source-logs-lateral-movement-detect`,
        "POST",
        { input_artifact_id: trafficId },
      ),
      call<{ artifacts: Array<{ artifact_id: string }> }>(
        `runs/${runId}/observations/multi-source-logs-privilege-escalation-detect`,
        "POST",
        { input_artifact_id: trafficId },
      ),
      call<{ artifacts: Array<{ artifact_id: string }> }>(
        `runs/${runId}/observations/multi-source-logs-dns-anomaly-detect`,
        "POST",
        { input_artifact_id: trafficId },
      ),
    ]);

    // ── Phase 2: Alarm observation ────────────────────────────────────────
    const threatsObs = await call<{ artifacts: Array<{ artifact_id: string }> }>(
      `runs/${runId}/observations/multi-source-logs-active-threats-detect`,
      "POST",
      { input_artifact_id: alarmId },
    );

    // ── Phase 2: Cross-source correlate (uses run's first input artifact) ─
    const crossObs = await call<{ artifacts: Array<{ artifact_id: string }> }>(
      `runs/${runId}/observations/multi-source-logs-cross-source-correlate`,
      "POST",
      { input_artifact_id: trafficId },
    );

    // ── Phase 2: Complete run ─────────────────────────────────────────────
    await call(`runs/${runId}/complete`, "POST");

    // ── Build result from observation artifacts ────────────────────────────
    // Fetch threat findings to determine severity
    const threatFindings = await fetchArtifactContents(threatsObs.artifacts ?? []);
    const crossFindings = await fetchArtifactContents(crossObs.artifacts ?? []);

    const severity = inferSeverity(threatFindings, crossFindings);
    const incidentCategories = inferCategories(threatFindings);
    const topAttackerIp = inferTopAttacker(threatFindings);

    // ── Phase 3 (optional): AI synthesis via platform-api /ai/chat ──────────
    // If CAI is available on the backend, use it to produce a richer summary.
    // Falls back to deterministic summary if unavailable.
    let evidenceSummary = buildSummary(threatFindings, crossFindings);
    let confidence = 0.85;
    let nistPhase = severity === "critical" || severity === "high" ? "containment" : "analysis";
    let recommendedActions = buildActions(severity, incidentCategories);

    try {
      const aiRes = await fetch(`${API}/ai/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: AbortSignal.timeout(45_000),
        body: JSON.stringify({
          message: (
            `Analyze this WatchGuard investigation and return a JSON object with these fields: ` +
            `evidence_summary (string), confidence (0-1 float), nist_phase (string), ` +
            `recommended_actions (array of strings). ` +
            `Context: workspace=${workspace_id}, severity=${severity}, ` +
            `categories=${incidentCategories.join(",")}, ` +
            `top_attacker=${topAttackerIp ?? "unknown"}, ` +
            `findings_count=${threatFindings.length + crossFindings.length}. ` +
            `Return ONLY the JSON object, no markdown.`
          ),
          client_id,
          context: { workspace_id, case_id: caseId, run_id: runId },
        }),
      });

      if (aiRes.ok) {
        const aiData = await aiRes.json();
        const reply = aiData.reply ?? "";
        // Try to parse JSON from the AI reply
        const jsonMatch = reply.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);
          if (parsed.evidence_summary) evidenceSummary = parsed.evidence_summary;
          if (typeof parsed.confidence === "number") confidence = parsed.confidence;
          if (parsed.nist_phase) nistPhase = parsed.nist_phase;
          if (Array.isArray(parsed.recommended_actions)) recommendedActions = parsed.recommended_actions;
        }
      }
    } catch {
      // CAI unavailable — use deterministic fallback (already set above)
    }

    const result = {
      case_id: caseId,
      run_id: runId,
      workspace_id,
      overall_severity: severity,
      confidence,
      incident_detected: severity !== "clean" && severity !== "unknown",
      incident_categories: incidentCategories,
      multi_stage_attack: crossFindings.length > 1,
      top_attacker_ip: topAttackerIp,
      top_targeted_user: null,
      nist_phase: nistPhase,
      recommended_actions: recommendedActions,
      evidence_summary: evidenceSummary,
    };

    // ── Store result as a case artifact for future cache retrieval ─────────
    call(`cases/${caseId}/artifacts/input`, "POST", {
      payload: { ...result, _subtype: "watchguard_investigation_result" },
      summary: `Investigation result — ${workspace_id}`,
      metadata: { subtype: "watchguard_investigation_result", workspace_id },
    }).catch(() => {});

    return NextResponse.json(result);
  } catch (e) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

// ── GET: return cached result for a workspace without re-running ─────────────
export async function GET(req: NextRequest) {
  const workspace_id = req.nextUrl.searchParams.get("workspace_id");
  const client_id = req.nextUrl.searchParams.get("client_id") ?? "egs";

  if (!workspace_id) return NextResponse.json({ cached: null });

  try {
    const casesData = await call<{
      cases: Array<{ case: { case_id: string; metadata: Record<string, unknown>; created_at: string } }>;
    }>(`cases?client_id=${client_id}&limit=100`);

    const wgCases = casesData.cases
      .map((c) => c.case)
      .filter((c) => c.metadata?.workspace_id === workspace_id && c.metadata?.source === "watchguard")
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

    for (const wgCase of wgCases) {
      const caseDetail = await call<{
        case: unknown;
        artifacts: Array<{ artifact_id: string }>;
      }>(`cases/${wgCase.case_id}`).catch(() => null);
      if (!caseDetail) continue;

      for (const artRef of caseDetail.artifacts ?? []) {
        const content = await call<{ artifact: unknown; content: Record<string, unknown> }>(
          `artifacts/${artRef.artifact_id}/content`,
        ).catch(() => null);
        if (!content?.content) continue;
        const c = content.content as Record<string, unknown>;
        if (c._subtype === "watchguard_investigation_result") {
          const { _subtype, ...result } = c;
          void _subtype;
          return NextResponse.json({ cached: { ...result, _cached_at: wgCase.created_at } });
        }
      }
    }

    return NextResponse.json({ cached: null });
  } catch {
    return NextResponse.json({ cached: null });
  }
}

async function fetchArtifactContents(artifacts: Array<{ artifact_id: string }>) {
  const results = await Promise.allSettled(
    artifacts.map((a) => call<Record<string, unknown>>(`artifacts/${a.artifact_id}/content`)),
  );
  return results
    .filter((r): r is PromiseFulfilledResult<Record<string, unknown>> => r.status === "fulfilled")
    .map((r) => r.value);
}

function inferSeverity(
  threats: Record<string, unknown>[],
  cross: Record<string, unknown>[],
): string {
  const all = [...threats, ...cross];
  if (all.some((f) => String(f.severity ?? "") === "critical")) return "critical";
  if (all.some((f) => String(f.severity ?? "") === "high")) return "high";
  if (all.some((f) => String(f.severity ?? "") === "medium")) return "medium";
  if (all.length > 0) return "low";
  return "clean";
}

function inferCategories(threats: Record<string, unknown>[]): string[] {
  const cats = new Set<string>();
  for (const t of threats) {
    const cat = String(t.alarm_type ?? t.category ?? "");
    if (cat) cats.add(cat.replace(/_/g, " ").toLowerCase());
  }
  return [...cats];
}

function inferTopAttacker(threats: Record<string, unknown>[]): string | null {
  for (const t of threats) {
    if (t.top_attacker_ip) return String(t.top_attacker_ip);
    if (t.src_ip) return String(t.src_ip);
  }
  return null;
}

function buildSummary(
  threats: Record<string, unknown>[],
  cross: Record<string, unknown>[],
): string {
  if (threats.length === 0 && cross.length === 0) {
    return "No significant threats detected in the analyzed log period.";
  }
  const parts: string[] = [];
  if (threats.length > 0) {
    parts.push(`${threats.length} active threat finding(s) from WatchGuard alarms.`);
  }
  if (cross.length > 0) {
    parts.push(`${cross.length} cross-source correlation(s) identified.`);
  }
  return parts.join(" ");
}

function buildActions(severity: string, categories: string[]): string[] {
  const actions: string[] = [];
  if (severity === "critical" || severity === "high") {
    actions.push("Immediately isolate affected network segments.");
    actions.push("Block attacking IP ranges at the perimeter firewall.");
  }
  if (categories.some((c) => c.includes("flood") || c.includes("ddos"))) {
    actions.push("Enable DDoS mitigation rules on the upstream provider.");
  }
  if (categories.some((c) => c.includes("scan"))) {
    actions.push("Review and tighten firewall allow rules for external IPs.");
  }
  if (actions.length === 0) {
    actions.push("Review logs in detail and monitor for escalation.");
  }
  return actions;
}
