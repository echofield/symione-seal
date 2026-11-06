// MCP face of the Seal: Streamable HTTP, JSON responses, single requests. Any MCP client (Claude Code included) can
// open a run, ask next, and report — the same engine as the JSON API.

import { KINDS } from '../core/policy';
import * as engine from './engine';
import { HttpError, json, readJson } from './http';

const SUPPORTED = ['2025-06-18', '2025-03-26', '2024-11-05'];

const INSTRUCTIONS = `SYMIONE SEAL: you prepare, a person seals the irreversible, the ledger keeps the trace.
Before any action that leaves your sandbox (sending, deploying to production, pushing main, publishing, paying, deleting, signing):
1. seal_open_run with your intent, plan and the actions in order (kinds from seal_policy).
2. For each action: call seal_next. "go" = do it now. "wait" = show the seal_url to your human, do NOT act, call seal_next again after they say they decided. "stop" = do not act; tell your human why.
3. After acting, seal_report the outcome; for sealed kinds include evidence (URL, message id, version id) and the receipt from seal_next.
Never perform a sealed action without a "go" that carries a receipt.`;

const actionSchema = {
  type: 'object',
  properties: {
    kind: { type: 'string', enum: Object.keys(KINDS), description: 'Action kind from the policy.' },
    summary: { type: 'string', description: 'One line a person can read on a phone: what exactly will happen.' },
    input: { type: 'object', description: 'The exact parameters of the action (recipient, subject, body, target, amount…). Its SHA-256 binds the seal.' },
  },
  required: ['kind', 'summary', 'input'],
};

const TOOLS = [
  {
    name: 'seal_policy', title: 'Seal policy',
    description: 'Lists action kinds (read, safe, sealed) and the limits.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'seal_open_run', title: 'Open a run',
    description: 'Declare an intent and the ordered actions you plan to take (1–8). Returns run_id. Sealed kinds will wait for a person.',
    inputSchema: {
      type: 'object',
      properties: {
        agent: { type: 'string', description: 'Who you are, e.g. "procurement-agent@acme".' },
        intent: { type: 'string' },
        plan: { type: 'array', items: { type: 'string' } },
        actions: { type: 'array', items: actionSchema, minItems: 1, maxItems: 8 },
        stop_conditions: { type: 'array', items: { type: 'string' } },
      },
      required: ['agent', 'intent', 'actions'],
    },
  },
  {
    name: 'seal_next', title: 'Ask for the next action',
    description: 'Returns go (act now; sealed kinds carry a receipt), wait (show seal_url to your human; do not act), stop, or done.',
    inputSchema: { type: 'object', properties: { run_id: { type: 'string' } }, required: ['run_id'] },
  },
  {
    name: 'seal_report', title: 'Report an action',
    description: 'Report the outcome of the current action. Sealed kinds reported done need evidence and their receipt.',
    inputSchema: {
      type: 'object',
      properties: {
        run_id: { type: 'string' }, index: { type: 'integer' }, outcome: { type: 'string', enum: ['done', 'failed'] },
        evidence: { type: 'object' }, receipt: { type: 'string' },
      },
      required: ['run_id', 'index', 'outcome'],
    },
  },
  {
    name: 'seal_status', title: 'Run status',
    description: 'The run, its actions, seal requests, receipts and ledger events.',
    inputSchema: { type: 'object', properties: { run_id: { type: 'string' } }, required: ['run_id'] },
  },
];

type Rpc = { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: unknown };
const rpcError = (id: unknown, code: number, message: string, status = 200) => json({ jsonrpc: '2.0', id: id ?? null, error: { code, message } }, status);
const rpcResult = (id: unknown, result: unknown) => json({ jsonrpc: '2.0', id, result });

async function callTool(ctx: engine.Ctx, name: string, args: Record<string, unknown>) {
  switch (name) {
    case 'seal_policy': return engine.policy();
    case 'seal_open_run': return engine.openRun(ctx, args);
    case 'seal_next': return engine.next(ctx, args.run_id);
    case 'seal_report': return engine.report(ctx, args.run_id, { index: args.index, outcome: args.outcome, evidence: args.evidence, receipt: args.receipt });
    case 'seal_status': return engine.status(ctx, args.run_id);
    default: return undefined;
  }
}

export async function handleMcp(request: Request, ctx: engine.Ctx): Promise<Response> {
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405, headers: { allow: 'POST' } });
  let msg: Rpc;
  try {
    msg = (await readJson(request, 512 * 1024)) as Rpc;
  } catch (e) {
    if (e instanceof HttpError && e.status === 413) return rpcError(null, -32600, e.message, 413);
    return rpcError(null, -32700, 'Parse error', 400);
  }
  if (Array.isArray(msg)) return rpcError(null, -32600, 'Batches are not supported.', 400);
  if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return rpcError(msg?.id, -32600, 'Invalid request', 400);
  const isNotification = !('id' in msg) || msg.id === undefined;
  if (isNotification) return new Response(null, { status: 202 });
  const params = (msg.params && typeof msg.params === 'object' ? msg.params : {}) as Record<string, unknown>;

  switch (msg.method) {
    case 'initialize': {
      const asked = typeof params.protocolVersion === 'string' ? params.protocolVersion : SUPPORTED[0];
      return rpcResult(msg.id, {
        protocolVersion: SUPPORTED.includes(asked) ? asked : SUPPORTED[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'symione-seal', title: 'SYMIONE SEAL', version: '0.1.0' },
        instructions: INSTRUCTIONS,
      });
    }
    case 'ping': return rpcResult(msg.id, {});
    case 'tools/list': return rpcResult(msg.id, { tools: TOOLS });
    case 'tools/call': {
      const name = typeof params.name === 'string' ? params.name : '';
      if (!TOOLS.some(t => t.name === name)) return rpcError(msg.id, -32602, `Unknown tool: ${name}`);
      const args = (params.arguments && typeof params.arguments === 'object' && !Array.isArray(params.arguments) ? params.arguments : {}) as Record<string, unknown>;
      try {
        const out = await callTool(ctx, name, args);
        return rpcResult(msg.id, { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }], structuredContent: out, isError: false });
      } catch (e) {
        if (!(e instanceof HttpError)) console.error('mcp tool failed', e instanceof Error ? e.stack ?? e.message : String(e));
        const error = e instanceof HttpError
          ? { error: { code: e.code, message: e.message, status: e.status } }
          : { error: { code: 'INTERNAL', message: 'Something went wrong on the Seal.', status: 500 } };
        return rpcResult(msg.id, { content: [{ type: 'text', text: JSON.stringify(error) }], structuredContent: error, isError: true });
      }
    }
    default: return rpcError(msg.id, -32601, `Method not found: ${msg.method}`);
  }
}
