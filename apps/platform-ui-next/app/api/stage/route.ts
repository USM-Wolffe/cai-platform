/**
 * Workspace staging orchestrator.
 *
 * After a ZIP is uploaded to S3 via presigned URL, this route:
 * 1. Finds the latest raw ZIP for the workspace
 * 2. Creates a watchguard_logs case + artifact + run
 * 3. Runs the watchguard-stage-workspace-zip observation
 * 4. Returns the staging_prefix from the manifest artifact
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
    return NextResponse.json(
      { error: "workspace_id and client_id are required" },
      { status: 400 },
    );
  }

  try {
    // 1. Find the latest raw ZIP for this workspace
    const uploadInfo = await call<{
      s3_uri: string;
      bucket: string;
      region: string;
    }>(`s3/workspaces/${workspace_id}/latest-upload`);

    // 2. Create a staging-only case under watchguard_logs
    const { case: stagingCase } = await call<{ case: { case_id: string } }>("cases", "POST", {
      client_id,
      workflow_type: "forensic_investigation",
      title: `WatchGuard Staging — ${workspace_id}`,
      summary: `Workspace staging for blue team investigation of ${workspace_id}.`,
      metadata: { source: "watchguard_staging", workspace_id },
    });
    const caseId = stagingCase.case_id;

    // 3. Attach the ZIP reference as input artifact
    const { artifact } = await call<{ artifact: { artifact_id: string } }>(
      `cases/${caseId}/artifacts/input`,
      "POST",
      {
        artifact_type: "watchguard_workspace_zip",
        payload: {
          source: "workspace_s3_zip",
          workspace: workspace_id,
          s3_uri: uploadInfo.s3_uri,
        },
      },
    );

    // 4. Create a run linked to the watchguard_logs backend
    const { run } = await call<{ run: { run_id: string } }>("runs", "POST", {
      case_id: caseId,
      backend_id: "watchguard_logs",
      input_artifact_ids: [artifact.artifact_id],
    });

    // 5. Run the staging observation
    const stagingResult = await call<{
      artifacts: Array<{ artifact_id: string; payload?: Record<string, unknown> }>;
      observation_result?: { structured_summary?: { staging_prefix?: string } };
    }>(
      `runs/${run.run_id}/observations/watchguard-stage-workspace-zip`,
      "POST",
      {
        input_artifact_ids: [artifact.artifact_id],
        requested_by: "platform-ui",
      },
    );

    // 6. Extract staging_prefix from the manifest artifact
    const stagingPrefix =
      stagingResult.observation_result?.structured_summary?.staging_prefix ??
      stagingResult.artifacts?.[0]?.payload?.["staging_prefix"];

    if (!stagingPrefix) {
      throw new Error(
        `Staging did not return a staging_prefix. Response: ${JSON.stringify(stagingResult)}`,
      );
    }

    return NextResponse.json({
      workspace_id,
      staging_prefix: stagingPrefix,
      case_id: caseId,
      run_id: run.run_id,
    });
  } catch (e) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
