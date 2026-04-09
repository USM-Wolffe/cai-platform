/**
 * AI chat endpoint — calls Anthropic Claude directly from the Next.js server.
 *
 * Requires ANTHROPIC_API_KEY env var. If absent, returns a helpful fallback.
 * Context (workspace_id, case_id, etc.) is injected into the system prompt.
 */

import { NextRequest, NextResponse } from "next/server";
import Anthropic from "@anthropic-ai/sdk";

const MODEL = process.env.CAI_MODEL ?? "claude-sonnet-4-6";

const SYSTEM_PROMPT = `You are a concise SOC (Security Operations Center) AI assistant embedded in the CAI Platform.
Help the analyst understand investigation results, explain findings, and recommend actions.
Be direct, specific, and brief. Answer in the same language the user uses.
When given investigation context, use it to make your answers specific and actionable.`;

export async function POST(req: NextRequest) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return NextResponse.json({
      reply:
        "AI assistant is not configured. Set ANTHROPIC_API_KEY in the environment to enable it.",
    });
  }

  const { message, context, history } = await req.json();

  // Build context description for the system prompt
  const contextLines: string[] = [];
  if (context?.workspace_id) contextLines.push(`Workspace: ${context.workspace_id}`);
  if (context?.case_id) contextLines.push(`Case ID: ${context.case_id}`);
  if (context?.run_id) contextLines.push(`Run ID: ${context.run_id}`);
  if (context?.page) contextLines.push(`Current page: ${context.page}`);
  const contextBlock = contextLines.length > 0
    ? `\n\nCurrent investigation context:\n${contextLines.join("\n")}`
    : "";

  // Build conversation history (last 6 messages = 3 turns)
  const messages: Anthropic.MessageParam[] = [];
  const recentHistory = (history ?? []).slice(-6) as Array<{ role: string; content: string }>;
  for (const msg of recentHistory) {
    if (msg.role === "user" || msg.role === "assistant") {
      messages.push({ role: msg.role, content: msg.content });
    }
  }
  messages.push({ role: "user", content: message });

  try {
    const client = new Anthropic({ apiKey });
    const response = await client.messages.create({
      model: MODEL,
      max_tokens: 1024,
      system: SYSTEM_PROMPT + contextBlock,
      messages,
    });

    const reply =
      response.content
        .filter((b) => b.type === "text")
        .map((b) => (b as Anthropic.TextBlock).text)
        .join("") || "No response.";

    return NextResponse.json({ reply });
  } catch (e) {
    const message = e instanceof Error ? e.message : "Unknown error";
    return NextResponse.json(
      { reply: `AI error: ${message}` },
      { status: 500 },
    );
  }
}
