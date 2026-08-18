import "reflect-metadata";
import { describe, expect, test, afterEach, spyOn } from "bun:test";
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  existsSync,
  statSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as x509Lib from "@peculiar/x509";
import {
  ensureTlsFiles,
  loadTlsFiles,
  loadAndValidateTlsFiles,
  loadClientBundle,
  loadClientBundleFromBase64,
  getClientBundleBase64,
  validateClientBundle,
} from "../../tls/store.ts";
import { keyToPem, pemToArrayBuffer } from "../../tls/utils.ts";

// Shared temp directory tracking for all describe blocks
const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "tls-store-test-"));
  tempDirs.push(dir);
  return dir;
}

async function generateFutureSelfSignedCert(name: string): Promise<string> {
  const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
  const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
  const cert = await x509Lib.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name,
    notBefore: new Date(Date.now() + 60_000),
    notAfter: new Date(Date.now() + 24 * 60 * 60 * 1000),
    keys,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
  });
  return cert.toString("pem");
}

async function generateRoleCertificate(
  caCertPem: string,
  caKeyPem: string,
  role: "server" | "client",
  subject: string,
  serverIdentities: "all" | "localhost-only" | "pre-docker-san" = "all",
): Promise<{ cert: string; key: string }> {
  const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
  const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
  const caKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(caKeyPem),
    algorithm,
    false,
    ["sign"],
  );
  const caCert = new x509Lib.X509Certificate(caCertPem);
  const extensions: x509Lib.Extension[] = [
    new x509Lib.BasicConstraintsExtension(false, undefined, true),
    new x509Lib.ExtendedKeyUsageExtension(
      [
        role === "server"
          ? x509Lib.ExtendedKeyUsage.serverAuth
          : x509Lib.ExtendedKeyUsage.clientAuth,
      ],
      true,
    ),
  ];
  if (role === "server") {
    const sanNames = {
      all: [
        { type: "dns" as const, value: "localhost" },
        { type: "dns" as const, value: "host.docker.internal" },
        { type: "ip" as const, value: "127.0.0.1" },
      ],
      "localhost-only": [{ type: "dns" as const, value: "localhost" }],
      "pre-docker-san": [
        { type: "dns" as const, value: "localhost" },
        { type: "ip" as const, value: "127.0.0.1" },
      ],
    }[serverIdentities];
    extensions.push(new x509Lib.SubjectAlternativeNameExtension(sanNames));
  }
  const cert = await x509Lib.X509CertificateGenerator.create({
    serialNumber: "02",
    subject,
    issuer: caCert.subject,
    notBefore: new Date(Date.now() - 1_000),
    notAfter: new Date(Date.now() + 24 * 60 * 60 * 1000),
    publicKey: keys.publicKey,
    signingKey: caKey,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions,
  });
  const privateKey = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
  return { cert: cert.toString("pem"), key: keyToPem(privateKey) };
}

afterEach(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  tempDirs.length = 0;
});

describe("ensureTlsFiles", () => {
  test("creates all TLS files when directory is empty", async () => {
    const dir = join(makeTempDir(), "tls");
    const files = await ensureTlsFiles(dir);

    expect(files.caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(files.caKey).toContain("-----BEGIN PRIVATE KEY-----");
    expect(files.serverCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(files.serverKey).toContain("-----BEGIN PRIVATE KEY-----");
    expect(files.clientCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(files.clientKey).toContain("-----BEGIN PRIVATE KEY-----");

    // Check files exist on disk
    expect(existsSync(join(dir, "ca.pem"))).toBe(true);
    expect(existsSync(join(dir, "ca-key.pem"))).toBe(true);
    expect(existsSync(join(dir, "server.pem"))).toBe(true);
    expect(existsSync(join(dir, "server-key.pem"))).toBe(true);
    expect(existsSync(join(dir, "client.pem"))).toBe(true);
    expect(existsSync(join(dir, "client-key.pem"))).toBe(true);
    expect(existsSync(join(dir, "client-bundle.pem"))).toBe(true);
  });

  test("creates directory with 0700 permissions", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    const stats = statSync(dir);
    expect(stats.mode & 0o777).toBe(0o700);
  });

  test("creates files with 0600 permissions", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    for (const file of [
      "ca.pem",
      "ca-key.pem",
      "server.pem",
      "server-key.pem",
      "client.pem",
      "client-key.pem",
      "client-bundle.pem",
    ]) {
      const stats = statSync(join(dir, file));
      expect(stats.mode & 0o777).toBe(0o600);
    }
  });

  test("is idempotent — does not regenerate valid certs", async () => {
    const dir = join(makeTempDir(), "tls");

    const first = await ensureTlsFiles(dir);
    const second = await ensureTlsFiles(dir);

    // Same certs should be returned
    expect(first.caCert).toBe(second.caCert);
    expect(first.serverCert).toBe(second.serverCert);
    expect(first.clientCert).toBe(second.clientCert);
  });

  test("force=true regenerates all certs even when valid", async () => {
    const dir = join(makeTempDir(), "tls");

    const first = await ensureTlsFiles(dir);
    const second = await ensureTlsFiles(dir, true);

    // New certs should be generated
    expect(first.caCert).not.toBe(second.caCert);
    expect(first.serverCert).not.toBe(second.serverCert);
    expect(first.clientCert).not.toBe(second.clientCert);
  });

  test("regenerates when server cert is expired (CA still valid)", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Replace server cert with an expired one, keep CA valid
    const x509 = await import("@peculiar/x509");
    const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
    const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const expiredCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=expired-server",
      notBefore: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      notAfter: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    });
    writeFileSync(join(dir, "server.pem"), expiredCert.toString("pem"));

    const warnSpy = await import("bun:test").then((m) =>
      m.spyOn(console, "warn").mockImplementation(() => {}),
    );
    const second = await ensureTlsFiles(dir);
    warnSpy.mockRestore();

    // Should have regenerated all certs
    expect(second.serverCert).not.toBe(expiredCert.toString("pem"));
    expect(second.caCert).toBeDefined();
  });

  test("regenerates when client cert is expired (CA still valid)", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Replace client cert with an expired one, keep CA valid
    const x509 = await import("@peculiar/x509");
    const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
    const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const expiredCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=expired-client",
      notBefore: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      notAfter: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    });
    writeFileSync(join(dir, "client.pem"), expiredCert.toString("pem"));

    const warnSpy = await import("bun:test").then((m) =>
      m.spyOn(console, "warn").mockImplementation(() => {}),
    );
    const second = await ensureTlsFiles(dir);
    warnSpy.mockRestore();

    expect(second.clientCert).not.toBe(expiredCert.toString("pem"));
  });

  test("regenerates when CA cert is expired", async () => {
    const dir = join(makeTempDir(), "tls");
    const first = await ensureTlsFiles(dir);

    // Replace the CA cert file with an already-expired cert to trigger regeneration
    const x509 = await import("@peculiar/x509");

    const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
    const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const expiredCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=expired",
      notBefore: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      notAfter: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
    });
    writeFileSync(join(dir, "ca.pem"), expiredCert.toString("pem"));

    const second = await ensureTlsFiles(dir);

    // Should have regenerated
    expect(second.caCert).not.toBe(first.caCert);
    expect(second.serverCert).not.toBe(first.serverCert);
  });

  test("leaves no temporary files behind after generation (atomic writes)", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    const leftovers = readdirSync(dir).filter((e) => e.endsWith(".tmp"));
    expect(leftovers).toEqual([]);
  });

  test("surfaces unsafe key material instead of silently rotating the CA", async () => {
    const dir = join(makeTempDir(), "tls");
    const first = await ensureTlsFiles(dir);

    // A permissions drift is an environmental problem, not invalid material:
    // regenerating here would rotate the CA and invalidate every distributed
    // client bundle when the actual fix is a chmod.
    chmodSync(join(dir, "ca-key.pem"), 0o640);
    await expect(ensureTlsFiles(dir)).rejects.toThrow(/permissions 640/);

    chmodSync(join(dir, "ca-key.pem"), 0o600);
    const after = await ensureTlsFiles(dir);
    expect(after.caCert).toBe(first.caCert);
    expect(after.serverCert).toBe(first.serverCert);
  });

  test("rebuilds a missing derived client bundle without rotating the certificate chain", async () => {
    const dir = join(makeTempDir(), "tls");
    const first = await ensureTlsFiles(dir);
    unlinkSync(join(dir, "client-bundle.pem"));

    const second = await ensureTlsFiles(dir);

    expect(second.caCert).toBe(first.caCert);
    expect(second.serverCert).toBe(first.serverCert);
    expect(second.clientCert).toBe(first.clientCert);
    expect(existsSync(join(dir, "client-bundle.pem"))).toBe(true);
    await expect(loadAndValidateTlsFiles(dir)).resolves.toEqual(second);
  });

  test("does not follow a planted fixed-name staging symlink during regeneration", async () => {
    const parent = makeTempDir();
    const dir = join(parent, "tls");
    const victim = join(parent, "victim");
    await ensureTlsFiles(dir);
    writeFileSync(victim, "do-not-overwrite", { mode: 0o600 });
    symlinkSync(victim, join(dir, "ca.pem.tmp"));

    await ensureTlsFiles(dir, true);

    expect(readFileSync(victim, "utf-8")).toBe("do-not-overwrite");
  });

  test("writes client-bundle.pem as well-formed PEM with newline-separated blocks", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    const bundle = readFileSync(join(dir, "client-bundle.pem"), "utf-8");
    // Concatenating PEM blocks without a separator glues the END/BEGIN markers
    // into a run of 10 dashes, which standard PEM parsers (openssl, curl,
    // python) reject.
    expect(bundle).not.toContain("----------");
    // The three expected blocks (CA cert, client cert, client key) must each be
    // recoverable as standalone PEM.
    const blocks = bundle.match(/-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/g);
    expect(blocks).toHaveLength(3);
  });
});

describe("loadTlsFiles", () => {
  test("loads previously generated TLS files", async () => {
    const dir = join(makeTempDir(), "tls");
    const generated = await ensureTlsFiles(dir);
    const loaded = loadTlsFiles(dir);

    expect(loaded.caCert).toBe(generated.caCert);
    expect(loaded.serverCert).toBe(generated.serverCert);
    expect(loaded.clientCert).toBe(generated.clientCert);
  });

  test("throws when files are missing", () => {
    expect(() => loadTlsFiles("/tmp/nonexistent-tls-dir")).toThrow();
  });
});

describe("loadAndValidateTlsFiles", () => {
  test("loads valid TLS files", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    const files = await loadAndValidateTlsFiles(dir);
    expect(files.caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(files.serverCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(files.clientCert).toContain("-----BEGIN CERTIFICATE-----");
  });

  test("throws with init-tls hint when certs are missing", async () => {
    const dir = join(makeTempDir(), "empty-tls");
    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/init-tls/);
  });

  test("rejects a symlinked TLS directory", async () => {
    const root = makeTempDir();
    const dir = join(root, "tls");
    const link = join(root, "tls-link");
    await ensureTlsFiles(dir);
    symlinkSync(dir, link);

    await expect(loadAndValidateTlsFiles(link)).rejects.toThrow(/directory.*symbolic link/s);
  });

  test("rejects a TLS directory accessible by group or other users", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    chmodSync(dir, 0o750);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/directory.*permissions 750/s);
  });

  test("reports unsafe TLS material instead of misdiagnosing it as missing", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    chmodSync(join(dir, "server-key.pem"), 0o640);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/permissions 640/);
    await expect(loadAndValidateTlsFiles(dir)).rejects.not.toThrow(/certificates not found/);
  });

  test("rejects symlinked TLS material", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const serverKeyPath = join(dir, "server-key.pem");
    unlinkSync(serverKeyPath);
    symlinkSync("client-key.pem", serverKeyPath);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/symbolic link/);
  });

  test("rejects non-regular TLS material", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const clientKeyPath = join(dir, "client-key.pem");
    unlinkSync(clientKeyPath);
    mkdirSync(clientKeyPath);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/not a regular file/);
  });

  test("rejects private key files accessible by group or other users", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    chmodSync(join(dir, "ca-key.pem"), 0o604);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/permissions 604/);
  });

  test("rejects private key files owned by a different user", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const realUid = process.getuid!();
    const uidSpy = spyOn(process, "getuid").mockReturnValue(realUid + 1);
    try {
      await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/owned by uid/);
    } finally {
      uidSpy.mockRestore();
    }
  });

  test("rejects a client bundle accessible by group or other users", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    chmodSync(join(dir, "client-bundle.pem"), 0o644);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/client bundle.*permissions 644/s);
  });

  test("throws when the CA certificate is not yet valid", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    writeFileSync(join(dir, "ca.pem"), await generateFutureSelfSignedCert("CN=future-ca"));

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/CA certificate is not yet valid/);
  });

  test("throws when the server certificate is not yet valid", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    writeFileSync(join(dir, "server.pem"), await generateFutureSelfSignedCert("CN=future-server"));

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(
      /server certificate is not yet valid/,
    );
  });

  test("throws when the client certificate is not yet valid", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    writeFileSync(join(dir, "client.pem"), await generateFutureSelfSignedCert("CN=future-client"));

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(
      /client certificate is not yet valid/,
    );
  });

  test("throws when the CA cert does not assert CA=true in BasicConstraints", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Replace ca.pem with a leaf certificate (BasicConstraints cA=false). The
    // extension is present, so merely checking for its existence is not enough
    // — the CA bit itself must be asserted.
    const leafCert = readFileSync(join(dir, "client.pem"), "utf-8");
    writeFileSync(join(dir, "ca.pem"), leafCert);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/CA=true/i);
  });

  test("throws when the CA certificate lacks keyCertSign usage", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
    const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const caWithoutKeyUsage = await x509Lib.X509CertificateGenerator.createSelfSigned({
      serialNumber: "03",
      name: "CN=gcp-authcalator CA",
      notBefore: new Date(Date.now() - 1_000),
      notAfter: new Date(Date.now() + 24 * 60 * 60 * 1000),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [new x509Lib.BasicConstraintsExtension(true, 0, true)],
    });
    writeFileSync(join(dir, "ca.pem"), caWithoutKeyUsage.toString("pem"));

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/keyCertSign/);
  });

  test("warns (without failing startup) when client-bundle.pem is stale", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Simulate a crash mid-regeneration that left an OLD bundle next to a
    // freshly written, self-consistent individual chain: overwrite
    // client-bundle.pem with a bundle from a different generation (different
    // CA). The gate doesn't consume the bundle, so it must still start — but it
    // should warn so the operator re-distributes the bundle.
    const otherDir = join(makeTempDir(), "tls-other");
    await ensureTlsFiles(otherDir);
    const staleBundle = readFileSync(join(otherDir, "client-bundle.pem"), "utf-8");
    writeFileSync(join(dir, "client-bundle.pem"), staleBundle);

    const warnSpy = spyOn(console, "warn").mockImplementation(() => {});
    try {
      const files = await loadAndValidateTlsFiles(dir);
      expect(files.caCert).toContain("-----BEGIN CERTIFICATE-----");
      const warned = warnSpy.mock.calls.map((c) => String(c[0])).join("\n");
      expect(warned).toMatch(/stale/i);
      expect(warned).toMatch(/init-tls/);
    } finally {
      warnSpy.mockRestore();
    }
  });

  test("warns when the stored client bundle key does not match its certificate", async () => {
    const dir = join(makeTempDir(), "tls");
    const files = await ensureTlsFiles(dir);
    const otherDir = join(makeTempDir(), "tls-other");
    const other = await ensureTlsFiles(otherDir);
    writeFileSync(
      join(dir, "client-bundle.pem"),
      `${files.caCert.trimEnd()}\n${files.clientCert.trimEnd()}\n${other.clientKey.trimEnd()}\n`,
    );

    const warnSpy = spyOn(console, "warn").mockImplementation(() => {});
    try {
      await expect(loadAndValidateTlsFiles(dir)).resolves.toBeDefined();
      expect(warnSpy.mock.calls.map((call) => String(call[0])).join("\n")).toMatch(/malformed/);
    } finally {
      warnSpy.mockRestore();
    }
  });

  test("throws with init-tls hint when CA cert is expired", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Replace the CA cert with an expired one
    const x509 = await import("@peculiar/x509");
    const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
    const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const expiredCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=expired",
      notBefore: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      notAfter: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
    });
    writeFileSync(join(dir, "ca.pem"), expiredCert.toString("pem"));

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/CA certificate has expired/);
    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/init-tls/);
  });

  test("throws when server cert is not signed by the CA", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Replace the server cert with one signed by a different CA
    const { generateCA } = await import("../../tls/ca.ts");
    const { generateServerCert } = await import("../../tls/certs.ts");
    const wrongCA = await generateCA();
    const wrongServerCert = await generateServerCert(wrongCA.caCert, wrongCA.caKey);
    writeFileSync(join(dir, "server.pem"), wrongServerCert.cert);
    writeFileSync(join(dir, "server-key.pem"), wrongServerCert.key);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(
      /server certificate signature is invalid/,
    );
    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/init-tls/);
  });

  test("throws when client cert is not signed by the CA", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Replace the client cert with one signed by a different CA
    const { generateCA } = await import("../../tls/ca.ts");
    const { generateClientCert } = await import("../../tls/certs.ts");
    const wrongCA = await generateCA();
    const wrongClientCert = await generateClientCert(wrongCA.caCert, wrongCA.caKey);
    writeFileSync(join(dir, "client.pem"), wrongClientCert.cert);
    writeFileSync(join(dir, "client-key.pem"), wrongClientCert.key);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(
      /client certificate signature is invalid/,
    );
    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/init-tls/);
  });

  test("throws when the CA private key does not match the CA certificate", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const otherDir = join(makeTempDir(), "tls-other");
    const other = await ensureTlsFiles(otherDir);
    writeFileSync(join(dir, "ca-key.pem"), other.caKey);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(
      /CA private key does not match its certificate/,
    );
  });

  test("throws when the server private key does not match its certificate", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const otherDir = join(makeTempDir(), "tls-other");
    const other = await ensureTlsFiles(otherDir);
    writeFileSync(join(dir, "server-key.pem"), other.serverKey);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(
      /server private key does not match its certificate/,
    );
  });

  test("throws when the client private key does not match its certificate", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const otherDir = join(makeTempDir(), "tls-other");
    const other = await ensureTlsFiles(otherDir);
    writeFileSync(join(dir, "client-key.pem"), other.clientKey);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(
      /client private key does not match its certificate/,
    );
  });

  test("throws when a private key is malformed", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    writeFileSync(
      join(dir, "server-key.pem"),
      "-----BEGIN PRIVATE KEY-----\ngarbage\n-----END PRIVATE KEY-----\n",
    );

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(
      /server private key is malformed or unsupported/,
    );
  });

  test("rejects a client certificate in the server certificate slot", async () => {
    const dir = join(makeTempDir(), "tls");
    const files = await ensureTlsFiles(dir);
    writeFileSync(join(dir, "server.pem"), files.clientCert);
    writeFileSync(join(dir, "server-key.pem"), files.clientKey);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/serverAuth-only/);
  });

  test("rejects a server certificate in the client certificate slot", async () => {
    const dir = join(makeTempDir(), "tls");
    const files = await ensureTlsFiles(dir);
    writeFileSync(join(dir, "client.pem"), files.serverCert);
    writeFileSync(join(dir, "client-key.pem"), files.serverKey);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/clientAuth-only/);
  });

  test("rejects an otherwise-valid server certificate with an unexpected identity", async () => {
    const dir = join(makeTempDir(), "tls");
    const files = await ensureTlsFiles(dir);
    const replacement = await generateRoleCertificate(
      files.caCert,
      files.caKey,
      "server",
      "CN=unexpected server",
    );
    writeFileSync(join(dir, "server.pem"), replacement.cert);
    writeFileSync(join(dir, "server-key.pem"), replacement.key);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/unexpected identity/);
  });

  test("rejects a server certificate missing required local identities", async () => {
    const dir = join(makeTempDir(), "tls");
    const files = await ensureTlsFiles(dir);
    const replacement = await generateRoleCertificate(
      files.caCert,
      files.caKey,
      "server",
      "CN=gcp-authcalator server",
      "localhost-only",
    );
    writeFileSync(join(dir, "server.pem"), replacement.cert);
    writeFileSync(join(dir, "server-key.pem"), replacement.key);

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/required local server identities/);
  });

  test("accepts a server certificate lacking only the host.docker.internal SAN (pre-#72 chain)", async () => {
    const dir = join(makeTempDir(), "tls");
    const files = await ensureTlsFiles(dir);
    const replacement = await generateRoleCertificate(
      files.caCert,
      files.caKey,
      "server",
      "CN=gcp-authcalator server",
      "pre-docker-san",
    );
    writeFileSync(join(dir, "server.pem"), replacement.cert);
    writeFileSync(join(dir, "server-key.pem"), replacement.key);

    const warnSpy = spyOn(console, "warn").mockImplementation(() => {});
    try {
      // Rejecting an older self-generated chain would brick a working gate on
      // upgrade; the missing devcontainer SAN is surfaced as a warning instead.
      const loaded = await loadAndValidateTlsFiles(dir);
      expect(loaded.serverCert).toBe(replacement.cert);
      const warnOutput = warnSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
      expect(warnOutput).toContain("host.docker.internal");
    } finally {
      warnSpy.mockRestore();
    }
  });

  test("throws when CA cert is malformed", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    writeFileSync(
      join(dir, "ca.pem"),
      "-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n",
    );

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/CA certificate is malformed/);
    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/init-tls/);
  });

  test("throws when server cert is malformed", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    writeFileSync(
      join(dir, "server.pem"),
      "-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n",
    );

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/server certificate is malformed/);
    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/init-tls/);
  });

  test("throws when client cert is malformed", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    writeFileSync(
      join(dir, "client.pem"),
      "-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n",
    );

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/client certificate is malformed/);
    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/init-tls/);
  });

  test("throws when CA cert is missing BasicConstraints", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Generate a self-signed cert WITHOUT BasicConstraints
    const x509 = await import("@peculiar/x509");
    const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
    const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const noBcCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=no-bc",
      notBefore: new Date(Date.now() - 1000),
      notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      extensions: [], // No BasicConstraints
    });
    writeFileSync(join(dir, "ca.pem"), noBcCert.toString("pem"));

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/BasicConstraints/);
  });

  test("throws when server cert has expired", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Replace server cert with an expired one signed by the same CA
    const x509 = await import("@peculiar/x509");
    const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
    const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const expiredCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "02",
      name: "CN=expired-server",
      notBefore: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      notAfter: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    });
    writeFileSync(join(dir, "server.pem"), expiredCert.toString("pem"));

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/server certificate has expired/);
  });

  test("throws when client cert has expired", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Replace client cert with an expired one
    const x509 = await import("@peculiar/x509");
    const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
    const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const expiredCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "03",
      name: "CN=expired-client",
      notBefore: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      notAfter: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    });
    writeFileSync(join(dir, "client.pem"), expiredCert.toString("pem"));

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(/client certificate has expired/);
  });

  test("throws when server cert issuer doesn't match CA subject", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Replace server cert with a self-signed cert (issuer != CA subject)
    const x509 = await import("@peculiar/x509");
    const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
    const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const selfSigned = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "04",
      name: "CN=wrong-issuer-server",
      notBefore: new Date(Date.now() - 1000),
      notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    });
    writeFileSync(join(dir, "server.pem"), selfSigned.toString("pem"));

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(
      /server certificate was not issued by the CA/,
    );
  });

  test("throws when client cert issuer doesn't match CA subject", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Replace client cert with a self-signed cert (issuer != CA subject)
    const x509 = await import("@peculiar/x509");
    const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
    const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const selfSigned = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "05",
      name: "CN=wrong-issuer-client",
      notBefore: new Date(Date.now() - 1000),
      notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    });
    writeFileSync(join(dir, "client.pem"), selfSigned.toString("pem"));

    await expect(loadAndValidateTlsFiles(dir)).rejects.toThrow(
      /client certificate was not issued by the CA/,
    );
  });
});

describe("loadClientBundle", () => {
  test("parses client-bundle.pem into CA cert, client cert, client key", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    const bundle = loadClientBundle(join(dir, "client-bundle.pem"));

    expect(bundle.caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientKey).toContain("-----BEGIN PRIVATE KEY-----");

    // CA cert should be different from client cert
    expect(bundle.caCert).not.toBe(bundle.clientCert);
  });

  test("auto-detects and decodes a base64-encoded bundle file", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Write a base64-encoded copy of the bundle
    const b64 = getClientBundleBase64(dir);
    const b64Path = join(dir, "client-bundle.b64");
    writeFileSync(b64Path, b64, { mode: 0o600 });
    chmodSync(b64Path, 0o600);

    const bundle = loadClientBundle(b64Path);

    expect(bundle.caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientKey).toContain("-----BEGIN PRIVATE KEY-----");

    // Should match the PEM-loaded bundle
    const pemBundle = loadClientBundle(join(dir, "client-bundle.pem"));
    expect(bundle.caCert).toBe(pemBundle.caCert);
    expect(bundle.clientCert).toBe(pemBundle.clientCert);
    expect(bundle.clientKey).toBe(pemBundle.clientKey);
  });

  test("reads a symlinked bundle file (Kubernetes secret mounts are symlinks)", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const linkPath = join(dir, "bundle-link.pem");
    symlinkSync("client-bundle.pem", linkPath);

    const bundle = loadClientBundle(linkPath);
    expect(bundle.caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientKey).toContain("-----BEGIN PRIVATE KEY-----");
  });

  test("reads a bundle file accessible by group or other users (bind mounts)", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const bundlePath = join(dir, "client-bundle.pem");
    chmodSync(bundlePath, 0o640);

    const bundle = loadClientBundle(bundlePath);
    expect(bundle.caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientKey).toContain("-----BEGIN PRIVATE KEY-----");
  });
});

describe("loadClientBundleFromBase64", () => {
  test("round-trips correctly with getClientBundleBase64", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    const b64 = getClientBundleBase64(dir);
    const bundle = loadClientBundleFromBase64(b64);

    expect(bundle.caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle.clientKey).toContain("-----BEGIN PRIVATE KEY-----");

    // Verify the decoded values match the original files
    const originalBundle = loadClientBundle(join(dir, "client-bundle.pem"));
    expect(bundle.caCert).toBe(originalBundle.caCert);
    expect(bundle.clientCert).toBe(originalBundle.clientCert);
    expect(bundle.clientKey).toBe(originalBundle.clientKey);
  });

  test("throws on invalid base64 content", () => {
    const invalidB64 = Buffer.from("not a PEM bundle").toString("base64");
    expect(() => loadClientBundleFromBase64(invalidB64)).toThrow(/Invalid client bundle/);
  });

  test("throws when bundle has only 1 PEM block", () => {
    const oneCert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    const b64 = Buffer.from(oneCert).toString("base64");
    expect(() => loadClientBundleFromBase64(b64)).toThrow(/expected 3 PEM blocks/);
  });

  test("throws when bundle has only 2 PEM blocks", () => {
    const twoCerts =
      "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n" +
      "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n";
    const b64 = Buffer.from(twoCerts).toString("base64");
    expect(() => loadClientBundleFromBase64(b64)).toThrow(/expected 3 PEM blocks/);
  });

  test("throws when bundle has 3 certs but no key", () => {
    const threeCerts =
      "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n" +
      "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n" +
      "-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----\n";
    const b64 = Buffer.from(threeCerts).toString("base64");
    expect(() => loadClientBundleFromBase64(b64)).toThrow(/expected 2 CERTIFICATE blocks/);
  });

  test("throws when bundle has unexpected PEM block type", () => {
    const badBundle =
      "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n" +
      "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n" +
      "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n";
    const b64 = Buffer.from(badBundle).toString("base64");
    expect(() => loadClientBundleFromBase64(b64)).toThrow(/unexpected PEM block type/);
  });

  test("parses correctly regardless of PEM block order", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    // Read the original bundle and rearrange: key first, then certs
    const originalBundle = loadClientBundle(join(dir, "client-bundle.pem"));
    const reordered = originalBundle.clientKey + originalBundle.caCert + originalBundle.clientCert;
    const b64 = Buffer.from(reordered).toString("base64");

    const bundle = loadClientBundleFromBase64(b64);

    expect(bundle.caCert).toBe(originalBundle.caCert);
    expect(bundle.clientCert).toBe(originalBundle.clientCert);
    expect(bundle.clientKey).toBe(originalBundle.clientKey);
  });
});

describe("validateClientBundle", () => {
  test("accepts a valid client bundle", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);

    const bundle = loadClientBundle(join(dir, "client-bundle.pem"));
    await expect(validateClientBundle(bundle)).resolves.toBeUndefined();
  });

  test("throws when CA cert is malformed", async () => {
    await expect(
      validateClientBundle({
        caCert: "-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n",
        clientCert: "-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----\n",
        clientKey: "-----BEGIN PRIVATE KEY-----\nbar\n-----END PRIVATE KEY-----\n",
      }),
    ).rejects.toThrow(/CA certificate is malformed/);
  });

  test("throws when client cert is malformed", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const bundle = loadClientBundle(join(dir, "client-bundle.pem"));

    await expect(
      validateClientBundle({
        ...bundle,
        clientCert: "-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n",
      }),
    ).rejects.toThrow(/client certificate is malformed/);
  });

  test("throws when CA cert has expired", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const bundle = loadClientBundle(join(dir, "client-bundle.pem"));

    // Create an expired CA cert
    const x509 = await import("@peculiar/x509");
    const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
    const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const expiredCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=expired-ca",
      notBefore: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      notAfter: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    });

    await expect(
      validateClientBundle({ ...bundle, caCert: expiredCert.toString("pem") }),
    ).rejects.toThrow(/CA certificate has expired/);
  });

  test("throws when client cert has expired", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const bundle = loadClientBundle(join(dir, "client-bundle.pem"));

    const x509 = await import("@peculiar/x509");
    const algorithm = { name: "ECDSA" as const, namedCurve: "P-256" as const };
    const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const expiredCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "02",
      name: "CN=expired-client",
      notBefore: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
      notAfter: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
      keys,
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    });

    await expect(
      validateClientBundle({ ...bundle, clientCert: expiredCert.toString("pem") }),
    ).rejects.toThrow(/client certificate has expired/);
  });

  test("throws when CA cert is not yet valid", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const bundle = loadClientBundle(join(dir, "client-bundle.pem"));

    await expect(
      validateClientBundle({
        ...bundle,
        caCert: await generateFutureSelfSignedCert("CN=future-ca"),
      }),
    ).rejects.toThrow(/CA certificate is not yet valid/);
  });

  test("throws when client cert is not yet valid", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const bundle = loadClientBundle(join(dir, "client-bundle.pem"));

    await expect(
      validateClientBundle({
        ...bundle,
        clientCert: await generateFutureSelfSignedCert("CN=future-client"),
      }),
    ).rejects.toThrow(/client certificate is not yet valid/);
  });

  test("throws when client private key does not match its certificate", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const bundle = loadClientBundle(join(dir, "client-bundle.pem"));
    const otherDir = join(makeTempDir(), "tls-other");
    const other = await ensureTlsFiles(otherDir);

    await expect(validateClientBundle({ ...bundle, clientKey: other.clientKey })).rejects.toThrow(
      /client private key does not match its certificate/,
    );
  });

  test("rejects a server certificate used as a client identity", async () => {
    const dir = join(makeTempDir(), "tls");
    const files = await ensureTlsFiles(dir);

    await expect(
      validateClientBundle({
        caCert: files.caCert,
        clientCert: files.serverCert,
        clientKey: files.serverKey,
      }),
    ).rejects.toThrow(/clientAuth-only/);
  });

  test("rejects an otherwise-valid client certificate with an unexpected identity", async () => {
    const dir = join(makeTempDir(), "tls");
    const files = await ensureTlsFiles(dir);
    const replacement = await generateRoleCertificate(
      files.caCert,
      files.caKey,
      "client",
      "CN=unexpected client",
    );

    await expect(
      validateClientBundle({
        caCert: files.caCert,
        clientCert: replacement.cert,
        clientKey: replacement.key,
      }),
    ).rejects.toThrow(/unexpected identity/);
  });

  test("throws when client cert was not signed by bundle CA", async () => {
    const dir = join(makeTempDir(), "tls");
    await ensureTlsFiles(dir);
    const bundle = loadClientBundle(join(dir, "client-bundle.pem"));

    // Generate a different CA and use its cert as the bundle CA.
    // Since both CAs use the same subject (CN=gcp-authcalator CA), the issuer
    // check passes but the signature verification fails.
    const { generateCA } = await import("../../tls/ca.ts");
    const wrongCA = await generateCA();

    await expect(validateClientBundle({ ...bundle, caCert: wrongCA.caCert })).rejects.toThrow(
      /client certificate signature is invalid/,
    );
  });
});
