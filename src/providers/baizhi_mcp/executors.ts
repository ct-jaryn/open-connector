import type { CredentialValidators, ProviderExecutors } from "../../core/types.ts";
import type { McpToolOptions, McpToolSummary } from "../mcp-tools.ts";
import type { ApiKeyProviderContext, ProviderFetch } from "../provider-runtime.ts";

import { sha256Hex } from "../../core/aws-sigv4.ts";
import { optionalRecord } from "../../core/cast.ts";
import { callMcpTool, listMcpTools } from "../mcp-tools.ts";
import {
  defineApiKeyProviderExecutors,
  mapProviderActionHandlers,
  ProviderRequestError,
  requiredInputString,
} from "../provider-runtime.ts";
import { baizhiMcpActions } from "./actions.ts";

const service = "baizhi_mcp";
const endpoint = "https://agent-toolkit.app.baizhi.cloud/mcp";
const allowedToolNames = new Set(["websearch_search", "web_scrape", "web_extract"]);

const handlers = mapProviderActionHandlers(
  service,
  baizhiMcpActions,
  (_action, actionName) => async (input: Record<string, unknown>, context: ApiKeyProviderContext) => {
    const connection = connectionInput(context.apiKey, context.fetcher, context.signal);
    if (actionName === "list_tools") {
      const tools = await safeMcpRequest(context.apiKey, () => listMcpTools(connection, { includeAnnotations: true }));
      return { tools: selectReadableTools(tools) };
    }

    const toolName = requiredInputString(input.toolName, "toolName");
    if (!allowedToolNames.has(toolName)) {
      throw new ProviderRequestError(400, "Only Baizhi web search, page reading, and extraction tools are supported");
    }
    return {
      result: await safeMcpRequest(context.apiKey, () =>
        callMcpTool({
          ...connection,
          toolName,
          arguments: optionalRecord(input.arguments) ?? {},
          authorizeTool(tool) {
            if (!tool || !isReadableTool(tool)) {
              throw new ProviderRequestError(400, `Baizhi MCP tool ${toolName} is unavailable or not read-only`);
            }
          },
        }),
      ),
    };
  },
);

export const executors: ProviderExecutors = defineApiKeyProviderExecutors(service, handlers, {
  skipDnsValidation: true,
});

export const credentialValidators: CredentialValidators = {
  async apiKey(input, { fetcher, signal }) {
    const key = requiredInputString(input.apiKey, "Baizhi API Key");
    const tools = await safeMcpRequest(
      key,
      () => listMcpTools(connectionInput(key, fetcher, signal), { includeAnnotations: true }),
      true,
    );
    if (selectReadableTools(tools).length === 0) {
      throw new ProviderRequestError(400, "Baizhi MCP did not advertise a supported read-only web tool");
    }
    const hash = sha256Hex(key).slice(0, 16);
    return {
      profile: { accountId: `baizhi-mcp:${hash}`, displayName: `Baizhi Cloud · ${hash.slice(-6)}` },
      metadata: { mcpEndpoint: endpoint },
    };
  },
};

function connectionInput(key: string, fetcher: ProviderFetch, signal?: AbortSignal): McpToolOptions {
  const apiKey = requiredInputString(key, "Baizhi API Key");
  if (/^Bearer\s+/i.test(apiKey)) {
    throw new ProviderRequestError(400, "Paste the Baizhi API Key without the Bearer prefix");
  }
  return {
    endpoint,
    service: "Baizhi",
    fetcher,
    headers: { authorization: `Bearer ${apiKey}` },
    redirect: "error",
    terminateSession: true,
    signal,
    maxResponseBytes: 8 * 1024 * 1024,
    toolListMaxBytes: 2 * 1024 * 1024,
    toolListMaxPages: 20,
    toolListMaxTools: 1_000,
  };
}

function isReadableTool(tool: McpToolSummary): boolean {
  return (
    allowedToolNames.has(tool.name) &&
    tool.annotations?.readOnlyHint !== false &&
    tool.annotations?.destructiveHint !== true
  );
}

function selectReadableTools(tools: McpToolSummary[]): McpToolSummary[] {
  const selected = tools.filter((tool) => allowedToolNames.has(tool.name));
  const names = new Set<string>();
  for (const tool of selected) {
    if (names.has(tool.name)) {
      throw new ProviderRequestError(502, "Baizhi MCP tools/list returned duplicate web tool names");
    }
    names.add(tool.name);
  }
  return selected.filter(isReadableTool);
}

async function safeMcpRequest<T>(key: string, request: () => Promise<T>, validatingCredential = false): Promise<T> {
  try {
    return await request();
  } catch (error) {
    if (!(error instanceof ProviderRequestError)) throw error;
    const rawKey = key.trim();
    const encodedKey = encodeURIComponent(rawKey);
    const message = error.message.split(rawKey).join("[redacted]").split(encodedKey).join("[redacted]");
    const unauthorized = error.status === 401 || error.status === 403;
    const status = validatingCredential && unauthorized ? 400 : error.status;
    const code = unauthorized ? (validatingCredential ? "invalid_input" : "authorization_failed") : error.code;
    throw new ProviderRequestError(status, message, undefined, code);
  }
}
