import "reflect-metadata";
import { randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import * as x509 from "@peculiar/x509";
import { generateCA } from "./ca.ts";
import { generateServerCert, generateClientCert } from "./certs.ts";
import { ensurePrivateDir } from "../gate/dir-utils.ts";
import { pemToArrayBuffer } from "./utils.ts";

export interface TlsFiles {
  caCert: string;
  caKey: string;
  serverCert: string;
  serverKey: string;
  clientCert: string;
  clientKey: string;
}

export interface ClientBundle {
  caCert: string;
  clientCert: string;
  clientKey: string;
}

const DEFAULT_TLS_DIR = join(homedir(), ".gcp-authcalator", "tls");

/**
 * Ensure all TLS certificate files exist and are valid.
 * Generates or regenerates as needed.
 *
 * Returns the loaded PEM contents.
 */
export async function ensureTlsFiles(tlsDir?: string, force?: boolean): Promise<TlsFiles> {
  const dir = tlsDir ?? DEFAULT_TLS_DIR;
  // ensurePrivateDir refuses pre-existing dirs with loose perms or
  // foreign ownership (an attacker could otherwise plant a writable
  // tls dir before init-tls runs and snapshot keys as they're written).
  ensurePrivateDir(dir, 0o700);

  const paths = tlsPaths(dir);

  // client-bundle.pem is derived from the authoritative six chain files. Its
  // loss or corruption must not rotate the CA and invalidate every distributed
  // remote bundle; a valid chain can reconstruct it exactly.
  const chainPaths = [
    paths.caCert,
    paths.caKey,
    paths.serverCert,
    paths.serverKey,
    paths.clientCert,
    paths.clientKey,
  ];
  const allChainFilesExist = chainPaths.every((p) => existsSync(p));

  if (allChainFilesExist && !force) {
    try {
      const files = await loadAndValidateTlsFiles(dir, { validateStoredClientBundle: false });
      writeClientBundle(paths.clientBundle, files.caCert, files.clientCert, files.clientKey);
      return files;
    } catch (err) {
      const detail = err instanceof Error ? err.message.split("\n", 1)[0] : String(err);
      console.warn(`tls: existing TLS material is invalid — regenerating it (${detail})`);
      console.warn("tls: Remote client bundles need updating!");
    }
  }

  // Generate everything fresh
  const ca = await generateCA();
  const server = await generateServerCert(ca.caCert, ca.caKey);
  const client = await generateClientCert(ca.caCert, ca.caKey);

  writeSecure(paths.caCert, ca.caCert);
  writeSecure(paths.caKey, ca.caKey);
  writeSecure(paths.serverCert, server.cert);
  writeSecure(paths.serverKey, server.key);
  writeSecure(paths.clientCert, client.cert);
  writeSecure(paths.clientKey, client.key);

  // Write combined client bundle. Join with newlines and normalize trailing
  // whitespace so PEM blocks stay separated — @peculiar's toString("pem") has
  // no trailing newline, and a bare concatenation glues END/BEGIN markers
  // together into invalid PEM that openssl/curl/python reject.
  writeClientBundle(paths.clientBundle, ca.caCert, client.cert, client.key);

  return {
    caCert: ca.caCert,
    caKey: ca.caKey,
    serverCert: server.cert,
    serverKey: server.key,
    clientCert: client.cert,
    clientKey: client.key,
  };
}

/**
 * Load and validate TLS files from disk.
 *
 * Unlike `ensureTlsFiles`, this does NOT generate certificates — it only loads
 * existing ones and validates that they are well-formed, not expired, and that
 * the server/client certificates are properly signed by the CA.
 *
 * Throws actionable errors when files are missing, invalid, or expired.
 */
export async function loadAndValidateTlsFiles(
  tlsDir?: string,
  options: { validateStoredClientBundle?: boolean } = {},
): Promise<TlsFiles> {
  const dir = tlsDir ?? DEFAULT_TLS_DIR;
  const hint = `\n  Run 'gcp-authcalator init-tls' to regenerate the certificate chain.`;

  let files: TlsFiles;
  try {
    files = loadTlsFiles(dir);
  } catch (err) {
    if (err instanceof TlsMaterialError && err.reason === "missing") {
      throw new Error(`TLS certificates not found in ${dir}\n  ${err.message}` + hint, {
        cause: err,
      });
    }
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(
      `TLS certificate material could not be loaded safely from ${dir}\n  ${detail}` + hint,
      {
        cause: err,
      },
    );
  }

  // Validate that all PEM content is parseable as X.509 certificates
  let caCert: x509.X509Certificate;
  try {
    caCert = new x509.X509Certificate(files.caCert);
  } catch {
    throw new Error(`TLS CA certificate is malformed in ${dir}` + hint);
  }

  let serverCert: x509.X509Certificate;
  try {
    serverCert = new x509.X509Certificate(files.serverCert);
  } catch {
    throw new Error(`TLS server certificate is malformed in ${dir}` + hint);
  }

  let clientCert: x509.X509Certificate;
  try {
    clientCert = new x509.X509Certificate(files.clientCert);
  } catch {
    throw new Error(`TLS client certificate is malformed in ${dir}` + hint);
  }

  validateCertificateTime(caCert, "TLS CA certificate", ` in ${dir}` + hint);
  validateCertificateTime(serverCert, "TLS server certificate", ` in ${dir}` + hint);
  validateCertificateTime(clientCert, "TLS client certificate", ` in ${dir}` + hint);

  validateCaCertificate(caCert, `TLS CA certificate`, ` in ${dir}` + hint);
  await validatePrivateKey(caCert, files.caKey, "TLS CA", ` in ${dir}` + hint);

  // Validate that server and client certs were signed by this CA
  const caPublicKey = await caCert.publicKey.export();
  if (serverCert.issuer !== caCert.subject) {
    throw new Error(
      `TLS server certificate was not issued by the CA in ${dir}` +
        `\n  Server issuer: ${serverCert.issuer}` +
        `\n  CA subject:    ${caCert.subject}` +
        hint,
    );
  }
  try {
    const serverValid = await serverCert.verify({ publicKey: caPublicKey, signatureOnly: true });
    if (!serverValid) {
      throw new Error(`TLS server certificate signature is invalid in ${dir}` + hint);
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes(dir)) throw err;
    throw new Error(`TLS server certificate signature verification failed in ${dir}` + hint);
  }

  if (clientCert.issuer !== caCert.subject) {
    throw new Error(
      `TLS client certificate was not issued by the CA in ${dir}` +
        `\n  Client issuer: ${clientCert.issuer}` +
        `\n  CA subject:    ${caCert.subject}` +
        hint,
    );
  }
  try {
    const clientValid = await clientCert.verify({ publicKey: caPublicKey, signatureOnly: true });
    if (!clientValid) {
      throw new Error(`TLS client certificate signature is invalid in ${dir}` + hint);
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes(dir)) throw err;
    throw new Error(`TLS client certificate signature verification failed in ${dir}` + hint);
  }

  validateLeafCertificate(serverCert, "server", ` in ${dir}` + hint);
  validateLeafCertificate(clientCert, "client", ` in ${dir}` + hint);
  await validatePrivateKey(serverCert, files.serverKey, "TLS server", ` in ${dir}` + hint);
  await validatePrivateKey(clientCert, files.clientKey, "TLS client", ` in ${dir}` + hint);

  // If a client bundle is present, warn (but don't fail startup) when it no
  // longer matches the on-disk chain. A crash during regeneration can leave a
  // stale bundle (old CA) beside a freshly written individual chain: the gate
  // doesn't consume the bundle, so it starts fine on the validated individual
  // chain — but remote clients shipping the stale bundle would fail the mTLS
  // handshake with an opaque error. Surface it so the operator re-distributes,
  // without taking the gate down over a client-only artifact.
  const bundlePath = tlsPaths(dir).clientBundle;
  let bundleContent: string | undefined;
  if (options.validateStoredClientBundle !== false) {
    try {
      bundleContent = readTlsMaterial(bundlePath, "client bundle", true);
    } catch (err) {
      if (!(err instanceof TlsMaterialError && err.reason === "missing")) {
        const detail = err instanceof Error ? err.message : String(err);
        throw new Error(
          `TLS client bundle could not be loaded safely from ${dir}\n  ${detail}` + hint,
          { cause: err },
        );
      }
    }
  }
  if (bundleContent !== undefined) {
    try {
      const bundle = parseClientBundle(bundleContent);
      const bundleCaSerial = new x509.X509Certificate(bundle.caCert).serialNumber;
      const bundleClientSerial = new x509.X509Certificate(bundle.clientCert).serialNumber;
      if (
        bundleCaSerial !== caCert.serialNumber ||
        bundleClientSerial !== clientCert.serialNumber
      ) {
        console.warn(
          `tls: client-bundle.pem in ${dir} is stale (its certificates do not match the active chain).` +
            `\n  Re-run 'gcp-authcalator init-tls' and re-distribute the bundle to remote clients.`,
        );
      } else {
        await validateClientBundle(bundle);
      }
    } catch {
      console.warn(
        `tls: client-bundle.pem in ${dir} is malformed and may be unusable by remote clients.` +
          `\n  Re-run 'gcp-authcalator init-tls' to regenerate it.`,
      );
    }
  }

  return files;
}

/**
 * Validate a client bundle's certificates are well-formed, not expired, and
 * that the client certificate is signed by the bundle's CA.
 *
 * Throws actionable errors with regeneration instructions.
 */
export async function validateClientBundle(bundle: ClientBundle): Promise<void> {
  const hint =
    "\n  On the host, run 'gcp-authcalator init-tls' to regenerate certificates," +
    "\n  then update the client bundle (GCP_AUTHCALATOR_TLS_BUNDLE_B64 or --tls-bundle).";

  let caCert: x509.X509Certificate;
  try {
    caCert = new x509.X509Certificate(bundle.caCert);
  } catch {
    throw new Error("TLS client bundle: CA certificate is malformed" + hint);
  }

  let clientCert: x509.X509Certificate;
  try {
    clientCert = new x509.X509Certificate(bundle.clientCert);
  } catch {
    throw new Error("TLS client bundle: client certificate is malformed" + hint);
  }

  validateCertificateTime(caCert, "TLS client bundle: CA certificate", hint);
  validateCertificateTime(clientCert, "TLS client bundle: client certificate", hint);
  validateCaCertificate(caCert, "TLS client bundle: CA certificate", hint);
  validateLeafCertificate(clientCert, "client", hint, "TLS client bundle: client certificate");
  await validatePrivateKey(clientCert, bundle.clientKey, "TLS client bundle: client", hint);

  // Validate the client cert was signed by the bundle's CA
  if (clientCert.issuer !== caCert.subject) {
    throw new Error(
      "TLS client bundle: client certificate was not issued by the bundle CA" +
        `\n  Client issuer: ${clientCert.issuer}` +
        `\n  CA subject:    ${caCert.subject}` +
        hint,
    );
  }
  try {
    const caPublicKey = await caCert.publicKey.export();
    const valid = await clientCert.verify({ publicKey: caPublicKey, signatureOnly: true });
    if (!valid) {
      throw new Error("TLS client bundle: client certificate signature is invalid" + hint);
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes("TLS client bundle")) throw err;
    throw new Error("TLS client bundle: client certificate signature verification failed" + hint);
  }
}

/** Load TLS files from disk. Throws if files are missing. */
export function loadTlsFiles(tlsDir?: string): TlsFiles {
  const dir = tlsDir ?? DEFAULT_TLS_DIR;
  validateTlsDirectory(dir);
  const paths = tlsPaths(dir);

  return {
    caCert: readTlsMaterial(paths.caCert, "CA certificate", false),
    caKey: readTlsMaterial(paths.caKey, "CA private key", true),
    serverCert: readTlsMaterial(paths.serverCert, "server certificate", false),
    serverKey: readTlsMaterial(paths.serverKey, "server private key", true),
    clientCert: readTlsMaterial(paths.clientCert, "client certificate", false),
    clientKey: readTlsMaterial(paths.clientKey, "client private key", true),
  };
}

/**
 * Load a client bundle from a file.
 *
 * Accepts either a PEM file (containing -----BEGIN blocks) or a base64-encoded
 * PEM file (as produced by `init-tls --bundle-b64`). Auto-detects the format.
 */
export function loadClientBundle(bundlePath: string): ClientBundle {
  const raw = readTlsMaterial(bundlePath, "client bundle", true).trim();

  // If the file contains PEM headers, parse directly.
  // Otherwise, assume base64-encoded PEM and decode first.
  const content = raw.includes("-----BEGIN ") ? raw : Buffer.from(raw, "base64").toString("utf-8");
  return parseClientBundle(content);
}

/** Decode a base64-encoded client bundle string into its PEM sections. */
export function loadClientBundleFromBase64(b64: string): ClientBundle {
  const content = Buffer.from(b64, "base64").toString("utf-8");
  return parseClientBundle(content);
}

/** Read client-bundle.pem and return as base64 string. */
export function getClientBundleBase64(tlsDir?: string): string {
  const dir = tlsDir ?? DEFAULT_TLS_DIR;
  const bundlePath = join(dir, "client-bundle.pem");
  const content = readTlsMaterial(bundlePath, "client bundle", true);
  return Buffer.from(content).toString("base64");
}

/** Get the TLS directory path. */
export function getDefaultTlsDir(): string {
  return DEFAULT_TLS_DIR;
}

// ---- Internal helpers ----

type TlsMaterialErrorReason = "missing" | "unsafe" | "unreadable";

class TlsMaterialError extends Error {
  constructor(
    readonly reason: TlsMaterialErrorReason,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "TlsMaterialError";
  }
}

function validateTlsDirectory(dir: string): void {
  let stat;
  try {
    stat = lstatSync(dir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new TlsMaterialError("missing", `TLS directory is missing at ${dir}`, { cause: err });
    }
    throw new TlsMaterialError("unreadable", `TLS directory cannot be inspected at ${dir}`, {
      cause: err,
    });
  }

  if (stat.isSymbolicLink()) {
    throw new TlsMaterialError(
      "unsafe",
      `TLS directory at ${dir} is a symbolic link — refusing to use it`,
    );
  }
  if (!stat.isDirectory()) {
    throw new TlsMaterialError(
      "unsafe",
      `TLS directory path ${dir} is not a directory — refusing to use it`,
    );
  }

  const uid = process.getuid?.();
  if (uid !== undefined && stat.uid !== uid) {
    throw new TlsMaterialError(
      "unsafe",
      `TLS directory at ${dir} is owned by uid ${stat.uid}, not the current user (uid ${uid}) — refusing to use it`,
    );
  }

  const permissions = stat.mode & 0o777;
  if ((permissions & 0o077) !== 0) {
    throw new TlsMaterialError(
      "unsafe",
      `TLS directory at ${dir} has permissions ${permissions.toString(8)} (octal); it must not be accessible by group or other users`,
    );
  }
}

/**
 * Read one TLS artifact without following symlinks.
 *
 * The pre-open check gives an actionable error for non-regular paths. The
 * O_NOFOLLOW open and post-open fstat close the check/use race: if an attacker
 * replaces the path after lstat, we still never read through a symlink and
 * still validate the file descriptor we actually consume.
 */
function readTlsMaterial(filePath: string, label: string, secret: boolean): string {
  let initialStat;
  try {
    initialStat = lstatSync(filePath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new TlsMaterialError("missing", `${label} is missing at ${filePath}`, { cause: err });
    }
    throw new TlsMaterialError("unreadable", `${label} cannot be inspected at ${filePath}`, {
      cause: err,
    });
  }

  if (initialStat.isSymbolicLink()) {
    throw new TlsMaterialError(
      "unsafe",
      `${label} at ${filePath} is a symbolic link — refusing to read it`,
    );
  }
  if (!initialStat.isFile()) {
    throw new TlsMaterialError(
      "unsafe",
      `${label} at ${filePath} is not a regular file — refusing to read it`,
    );
  }

  let fd: number;
  try {
    fd = openSync(filePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      throw new TlsMaterialError("missing", `${label} is missing at ${filePath}`, { cause: err });
    }
    if (code === "ELOOP") {
      throw new TlsMaterialError(
        "unsafe",
        `${label} at ${filePath} became a symbolic link — refusing to read it`,
        { cause: err },
      );
    }
    throw new TlsMaterialError("unreadable", `${label} cannot be opened at ${filePath}`, {
      cause: err,
    });
  }

  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) {
      throw new TlsMaterialError(
        "unsafe",
        `${label} at ${filePath} is not a regular file — refusing to read it`,
      );
    }

    if (secret) {
      const uid = process.getuid?.();
      if (uid !== undefined && stat.uid !== uid) {
        throw new TlsMaterialError(
          "unsafe",
          `${label} at ${filePath} is owned by uid ${stat.uid}, not the current user (uid ${uid}) — refusing to read it`,
        );
      }

      const permissions = stat.mode & 0o777;
      if ((permissions & 0o077) !== 0) {
        throw new TlsMaterialError(
          "unsafe",
          `${label} at ${filePath} has permissions ${permissions.toString(8)} (octal); private TLS material must not be accessible by group or other users`,
        );
      }
    }

    return readFileSync(fd, "utf-8");
  } catch (err) {
    if (err instanceof TlsMaterialError) throw err;
    throw new TlsMaterialError("unreadable", `${label} cannot be read at ${filePath}`, {
      cause: err,
    });
  } finally {
    closeSync(fd);
  }
}

function validateCertificateTime(cert: x509.X509Certificate, label: string, suffix: string): void {
  const now = Date.now();
  if (cert.notBefore.getTime() > now) {
    throw new Error(`${label} is not yet valid${suffix}`);
  }
  if (cert.notAfter.getTime() <= now) {
    throw new Error(`${label} has expired${suffix}`);
  }
}

function validateCaCertificate(cert: x509.X509Certificate, label: string, suffix: string): void {
  const basicConstraints = cert.getExtension(x509.BasicConstraintsExtension);
  if (!basicConstraints) {
    throw new Error(`${label} is missing BasicConstraints extension${suffix}`);
  }
  if (!basicConstraints.ca) {
    throw new Error(`${label} does not assert CA=true in BasicConstraints${suffix}`);
  }

  const keyUsages = cert.getExtension(x509.KeyUsagesExtension);
  if (!keyUsages || (keyUsages.usages & x509.KeyUsageFlags.keyCertSign) === 0) {
    throw new Error(`${label} is missing the keyCertSign key usage${suffix}`);
  }
}

function validateLeafCertificate(
  cert: x509.X509Certificate,
  role: "server" | "client",
  suffix: string,
  label = `TLS ${role} certificate`,
): void {
  const basicConstraints = cert.getExtension(x509.BasicConstraintsExtension);
  if (!basicConstraints || basicConstraints.ca) {
    throw new Error(`${label} must be an end-entity certificate (CA=false)${suffix}`);
  }

  const expectedUsage =
    role === "server" ? x509.ExtendedKeyUsage.serverAuth : x509.ExtendedKeyUsage.clientAuth;
  const oppositeUsage =
    role === "server" ? x509.ExtendedKeyUsage.clientAuth : x509.ExtendedKeyUsage.serverAuth;
  const extendedKeyUsage = cert.getExtension(x509.ExtendedKeyUsageExtension);
  if (
    !extendedKeyUsage ||
    !extendedKeyUsage.usages.includes(expectedUsage) ||
    extendedKeyUsage.usages.includes(oppositeUsage)
  ) {
    throw new Error(
      `${label} does not have the required ${role}Auth-only extended key usage${suffix}`,
    );
  }

  const expectedSubject = `CN=gcp-authcalator ${role}`;
  if (cert.subject !== expectedSubject) {
    throw new Error(
      `${label} has unexpected identity${suffix}\n  Subject:  ${cert.subject}\n  Expected: ${expectedSubject}`,
    );
  }

  if (role === "server") {
    const subjectAlternativeName = cert.getExtension(x509.SubjectAlternativeNameExtension);
    const names = subjectAlternativeName?.names.items ?? [];
    const hasLocalhost = names.some((name) => name.type === "dns" && name.value === "localhost");
    const hasDockerHost = names.some(
      (name) => name.type === "dns" && name.value === "host.docker.internal",
    );
    const hasLoopback = names.some((name) => name.type === "ip" && name.value === "127.0.0.1");
    if (!hasLocalhost || !hasDockerHost || !hasLoopback) {
      throw new Error(`${label} is missing the required local server identities${suffix}`);
    }
  }
}

async function validatePrivateKey(
  cert: x509.X509Certificate,
  privateKeyPem: string,
  label: string,
  suffix: string,
): Promise<void> {
  const keyAlgorithm = { name: "ECDSA", namedCurve: "P-256" } as const;
  let privateKey: CryptoKey;
  try {
    privateKey = await crypto.subtle.importKey(
      "pkcs8",
      pemToArrayBuffer(privateKeyPem),
      keyAlgorithm,
      false,
      ["sign"],
    );
  } catch (err) {
    throw new Error(`${label} private key is malformed or unsupported${suffix}`, { cause: err });
  }

  let publicKey: CryptoKey;
  try {
    publicKey = await cert.publicKey.export(keyAlgorithm, ["verify"]);
  } catch (err) {
    throw new Error(`${label} certificate public key is not ECDSA P-256${suffix}`, { cause: err });
  }

  const challenge = new TextEncoder().encode("gcp-authcalator TLS key-pair validation");
  try {
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      challenge,
    );
    const matches = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      signature,
      challenge,
    );
    if (!matches) {
      throw new Error(`${label} private key does not match its certificate${suffix}`);
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes("does not match its certificate")) throw err;
    throw new Error(`${label} private key could not be verified against its certificate${suffix}`, {
      cause: err,
    });
  }
}

function tlsPaths(dir: string) {
  return {
    caCert: join(dir, "ca.pem"),
    caKey: join(dir, "ca-key.pem"),
    serverCert: join(dir, "server.pem"),
    serverKey: join(dir, "server-key.pem"),
    clientCert: join(dir, "client.pem"),
    clientKey: join(dir, "client-key.pem"),
    clientBundle: join(dir, "client-bundle.pem"),
  };
}

function writeSecure(filePath: string, content: string): void {
  // Write to a sibling temp file then atomically rename into place, so a crash
  // mid-write can never leave a truncated key/cert at the real path. The temp
  // lives in the same (0700) directory, so the rename stays on one filesystem
  // and the secret is never world-visible.
  const tmpPath = `${filePath}.${randomBytes(12).toString("hex")}.tmp`;
  try {
    // Exclusive creation plus an unpredictable name prevents another same-UID
    // process from planting a symlink at the staging path and redirecting a
    // private-key write outside the TLS directory.
    writeFileSync(tmpPath, content, { mode: 0o600, flag: "wx" });
    renameSync(tmpPath, filePath);
  } finally {
    rmSync(tmpPath, { force: true });
  }
}

function writeClientBundle(
  bundlePath: string,
  caCert: string,
  clientCert: string,
  clientKey: string,
): void {
  const content = [caCert, clientCert, clientKey].map((pem) => pem.trimEnd()).join("\n") + "\n";
  writeSecure(bundlePath, content);
}

function parseClientBundle(content: string): ClientBundle {
  const pemBlocks = content.match(/-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/g);

  if (!pemBlocks || pemBlocks.length < 3) {
    throw new Error(
      `Invalid client bundle: expected 3 PEM blocks (CA cert, client cert, client key), found ${pemBlocks?.length ?? 0}`,
    );
  }

  // Parse by PEM label type rather than assuming fixed order
  const certs: string[] = [];
  const keys: string[] = [];

  for (const block of pemBlocks) {
    if (block.startsWith("-----BEGIN CERTIFICATE-----")) {
      certs.push(block + "\n");
    } else if (block.startsWith("-----BEGIN PRIVATE KEY-----")) {
      keys.push(block + "\n");
    } else {
      throw new Error(`Invalid client bundle: unexpected PEM block type: ${block.slice(0, 40)}...`);
    }
  }

  if (certs.length !== 2) {
    throw new Error(
      `Invalid client bundle: expected 2 CERTIFICATE blocks (CA + client), found ${certs.length}`,
    );
  }
  if (keys.length !== 1) {
    throw new Error(`Invalid client bundle: expected 1 PRIVATE KEY block, found ${keys.length}`);
  }

  return { caCert: certs[0]!, clientCert: certs[1]!, clientKey: keys[0]! };
}
