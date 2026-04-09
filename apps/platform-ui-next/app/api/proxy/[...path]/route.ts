import { NextRequest, NextResponse } from "next/server";

const PLATFORM_API = process.env.PLATFORM_API_BASE_URL ?? "http://localhost:8000";

async function proxy(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  const upstream = `${PLATFORM_API}/${path.join("/")}${req.nextUrl.search}`;

  const body = req.method !== "GET" && req.method !== "HEAD"
    ? await req.text()
    : undefined;

  const upstream_res = await fetch(upstream, {
    method: req.method,
    headers: { "Content-Type": "application/json" },
    body,
  });

  const data = await upstream_res.text();
  return new NextResponse(data, {
    status: upstream_res.status,
    headers: { "Content-Type": "application/json" },
  });
}

export { proxy as GET, proxy as POST, proxy as PUT, proxy as PATCH, proxy as DELETE };
