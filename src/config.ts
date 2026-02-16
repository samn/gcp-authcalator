import { z } from "zod";
import { parse as parseTOML } from "smol-toml";
import { readFileSync } from "node:fs";

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

export const ConfigSchema = z.object({
  project_id: z.string().min(1).optional(),
  service_account: z.email().optional(),
  socket_path: z.string().min(1).default("/tmp/gcp-authcalator.sock"),
  port: z.coerce.number().int().min(1).max(65535).default(8173),
});

export type Config = z.infer<typeof ConfigSchema>;

/** gate requires project_id and service_account. */
export const GateConfigSchema = ConfigSchema.required({
  project_id: true,
  service_account: true,
});

export type GateConfig = z.infer<typeof GateConfigSchema>;

/** metadata-proxy requires project_id. */
export const MetadataProxyConfigSchema = ConfigSchema.required({
  project_id: true,
});

export type MetadataProxyConfig = z.infer<typeof MetadataProxyConfigSchema>;

/** with-prod requires project_id. */
export const WithProdConfigSchema = ConfigSchema.required({
  project_id: true,
});

export type WithProdConfig = z.infer<typeof WithProdConfigSchema>;

// ---------------------------------------------------------------------------
// CLI-arg key mapping (kebab-case → snake_case)
// ---------------------------------------------------------------------------

const cliToConfigKey: Record<string, keyof Config> = {
  "project-id": "project_id",
  "service-account": "service_account",
  "socket-path": "socket_path",
  port: "port",
};

/** Convert a CLI-arg values object (kebab-case keys) to config keys (snake_case). */
export function mapCliArgs(
  cliValues: Record<string, string | boolean | undefined>,
): Record<string, unknown> {
  const mapped: Record<string, unknown> = {};
  for (const [cliKey, value] of Object.entries(cliValues)) {
    if (value === undefined) continue;
    const configKey = cliToConfigKey[cliKey];
    if (configKey) {
      mapped[configKey] = value;
    }
  }
  return mapped;
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

/** Read and parse a TOML config file. */
export function loadTOML(configPath: string): Record<string, unknown> {
  const content = readFileSync(configPath, "utf-8");
  return parseTOML(content) as Record<string, unknown>;
}

/**
 * Load configuration by merging TOML file values with CLI arg overrides,
 * then validating through the base ConfigSchema.
 *
 * Precedence: CLI args > TOML file > schema defaults.
 */
export function loadConfig(cliValues: Record<string, unknown>, configPath?: string): Config {
  const fileValues = configPath ? loadTOML(configPath) : {};
  const merged = { ...fileValues, ...cliValues };
  return ConfigSchema.parse(merged);
}
