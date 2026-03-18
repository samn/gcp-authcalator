import { z } from "zod";
import { parse as parseTOML } from "smol-toml";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// Runtime directory helpers
// ---------------------------------------------------------------------------

/**
 * Return a user-private directory for runtime files (sockets, temp data).
 *
 * Prefers $XDG_RUNTIME_DIR (typically /run/user/$UID, already 0o700).
 * Falls back to ~/.gcp-authcalator/.
 *
 * Using a user-private directory instead of /tmp eliminates TOCTOU symlink
 * races — no other user can create files inside the directory.
 */
export function getDefaultRuntimeDir(): string {
  const xdg = process.env.XDG_RUNTIME_DIR;
  if (xdg) return xdg;
  return join(homedir(), ".gcp-authcalator");
}

/** Default socket path inside the user-private runtime directory. */
export function getDefaultSocketPath(): string {
  return join(getDefaultRuntimeDir(), "gcp-authcalator.sock");
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/** Expand a leading `~` or `~/` to the user's home directory. */
export function expandTilde(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default OAuth scopes when none are configured. */
export const DEFAULT_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"];

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

export const ConfigSchema = z.object({
  project_id: z.string().min(1).optional(),
  service_account: z.email().optional(),
  socket_path: z.string().min(1).default(getDefaultSocketPath).transform(expandTilde),
  port: z.coerce.number().int().min(1).max(65535).default(8173),
  gate_tls_port: z.coerce.number().int().min(1).max(65535).optional(),
  tls_dir: z.string().min(1).transform(expandTilde).optional(),
  gate_url: z
    .string()
    .min(1)
    .refine((v) => v.startsWith("https://"), { message: "gate_url must use https://" })
    .optional(),
  tls_bundle: z.string().min(1).transform(expandTilde).optional(),
  scopes: z.array(z.string().min(1)).optional(),
  pam_policy: z.string().min(1).optional(),
  pam_allowed_policies: z.array(z.string().min(1)).optional(),
  pam_location: z.string().min(1).optional(),
});

export type Config = z.infer<typeof ConfigSchema>;

/**
 * gate requires project_id and at least one of service_account or pam_policy.
 * - service_account alone: dev tokens via impersonation, prod tokens via ADC
 * - pam_policy alone: prod tokens only (dev tokens disabled)
 * - both: dev tokens via impersonation, prod tokens with PAM escalation
 */
export const GateConfigSchema = ConfigSchema.required({
  project_id: true,
}).refine((c) => c.service_account || c.pam_policy, {
  message: "gate requires at least one of service_account or pam_policy",
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
  "gate-tls-port": "gate_tls_port",
  "tls-dir": "tls_dir",
  "gate-url": "gate_url",
  "tls-bundle": "tls_bundle",
  scopes: "scopes",
  "pam-policy": "pam_policy",
  "pam-allowed-policies": "pam_allowed_policies",
  "pam-location": "pam_location",
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
      // Split comma-separated values into arrays for list fields
      if (
        (configKey === "scopes" || configKey === "pam_allowed_policies") &&
        typeof value === "string"
      ) {
        mapped[configKey] = value.split(",").map((s) => s.trim());
      } else {
        mapped[configKey] = value;
      }
    }
  }
  return mapped;
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

/** All config keys that can be set via environment variables. */
const configKeys: readonly (keyof Config)[] = [
  "project_id",
  "service_account",
  "socket_path",
  "port",
  "gate_tls_port",
  "tls_dir",
  "gate_url",
  "tls_bundle",
  "pam_policy",
  "pam_location",
];

/**
 * Read config values from GCP_AUTHCALATOR_* environment variables.
 * Each config key maps to GCP_AUTHCALATOR_{KEY_UPPERCASED}.
 */
export function loadEnvVars(): Record<string, unknown> {
  const envValues: Record<string, unknown> = {};
  for (const key of configKeys) {
    const envKey = `GCP_AUTHCALATOR_${key.toUpperCase()}`;
    const value = process.env[envKey];
    if (value !== undefined) {
      envValues[key] = value;
    }
  }
  return envValues;
}

/** Read and parse a TOML config file. */
export function loadTOML(configPath: string): Record<string, unknown> {
  const content = readFileSync(configPath, "utf-8");
  return parseTOML(content) as Record<string, unknown>;
}

/**
 * Load configuration by merging TOML file values, CLI arg overrides, and
 * environment variables, then validating through the base ConfigSchema.
 *
 * Precedence: env vars > CLI args > TOML file > schema defaults.
 */
export function loadConfig(cliValues: Record<string, unknown>, configPath?: string): Config {
  const envValues = loadEnvVars();
  const fileValues = configPath ? loadTOML(configPath) : {};
  const merged = { ...fileValues, ...cliValues, ...envValues };
  return ConfigSchema.parse(merged);
}
