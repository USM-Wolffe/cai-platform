/**
 * WatchGuard workspace analytics route.
 *
 * Runs DDoS analytics observations on a staged workspace and returns:
 * - Top source IPs (bar chart data)
 * - Protocol breakdown (pie/bar chart data)
 * - Temporal events by day (line chart data)
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
    // 1. Discover the latest staging prefix
    const stagingInfo = await call<{
      staging_prefix: string;
      bucket: string;
      region: string;
    }>(`s3/workspaces/${workspace_id}/latest-staging`);

    const { staging_prefix, bucket } = stagingInfo;

    // 2. Create a minimal analytics case under watchguard_logs
    const { case: analyticsCase } = await call<{ case: { case_id: string } }>("cases", "POST", {
      client_id,
      title: `WatchGuard Analytics — ${workspace_id}`,
      metadata: { source: "watchguard_analytics", workspace_id },
    });
    const caseId = analyticsCase.case_id;

    // 3. Attach a staging manifest artifact (minimal fields required by _parse_staging_manifest)
    const { artifact } = await call<{ artifact: { artifact_id: string } }>(
      `cases/${caseId}/artifacts`,
      "POST",
      {
        artifact_type: "watchguard_staging_manifest",
        payload: {
          source: "workspace_staging",
          workspace: workspace_id,
          staging_prefix,
          bucket,
        },
      },
    );

    // 4. Create a run
    const { run } = await call<{ run: { run_id: string } }>("runs", "POST", {
      case_id: caseId,
      backend_id: "watchguard_logs",
      input_artifact_ids: [artifact.artifact_id],
    });
    const runId = run.run_id;

    const obsInput = { input_artifact_ids: [artifact.artifact_id] };

    // 5. Run analytics observations in parallel
    const [topSourcesRes, temporalRes, protocolRes] = await Promise.all([
      call<{ artifacts: Array<{ artifact_id: string }> }>(
        `runs/${runId}/observations/watchguard-ddos-top-sources`,
        "POST",
        obsInput,
      ).catch(() => ({ artifacts: [] })),
      call<{ artifacts: Array<{ artifact_id: string }> }>(
        `runs/${runId}/observations/watchguard-ddos-temporal-analysis`,
        "POST",
        obsInput,
      ).catch(() => ({ artifacts: [] })),
      call<{ artifacts: Array<{ artifact_id: string }> }>(
        `runs/${runId}/observations/watchguard-ddos-protocol-breakdown`,
        "POST",
        obsInput,
      ).catch(() => ({ artifacts: [] })),
    ]);

    await call(`runs/${runId}/complete`, "POST").catch(() => null);

    // 6. Fetch artifact contents
    const [topSourcesData, temporalData, protocolData] = await Promise.all([
      fetchArtifact(topSourcesRes.artifacts?.[0]?.artifact_id),
      fetchArtifact(temporalRes.artifacts?.[0]?.artifact_id),
      fetchArtifact(protocolRes.artifacts?.[0]?.artifact_id),
    ]);

    return NextResponse.json({
      workspace_id,
      top_sources: topSourcesData?.sources ?? [],
      segments: topSourcesData?.segments ?? [],
      total_events: topSourcesData?.total_events ?? 0,
      by_day: temporalData?.by_day ?? [],
      peak_day: temporalData?.peak_day ?? null,
      peak_events: temporalData?.peak_events ?? 0,
      date_range: temporalData?.date_range ?? null,
      protocols: protocolData?.protocols ?? [],
    });
  } catch (e) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

async function fetchArtifact(
  artifactId: string | undefined,
): Promise<Record<string, unknown> | null> {
  if (!artifactId) return null;
  try {
    return await call<Record<string, unknown>>(`artifacts/${artifactId}/content`);
  } catch {
    return null;
  }
}
