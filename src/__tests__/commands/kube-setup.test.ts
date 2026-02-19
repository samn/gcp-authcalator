import { describe, expect, test, beforeEach, afterEach, spyOn } from "bun:test";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runKubeSetup, patchKubeconfig } from "../../commands/kube-setup.ts";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const parseYAML = (input: string) => Bun.YAML.parse(input) as any;

const SAMPLE_KUBECONFIG = `apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: REDACTED
    server: https://10.0.0.1
  name: gke_my-project_us-central1_my-cluster
contexts:
- context:
    cluster: gke_my-project_us-central1_my-cluster
    user: gke_my-project_us-central1_my-cluster
  name: gke_my-project_us-central1_my-cluster
current-context: gke_my-project_us-central1_my-cluster
users:
- name: gke_my-project_us-central1_my-cluster
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: gke-gcloud-auth-plugin
      installHint: Install gke-gcloud-auth-plugin
      provideClusterInfo: true
`;

const MULTI_USER_KUBECONFIG = `apiVersion: v1
kind: Config
users:
- name: gke_proj-a_us-west1_cluster-a
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: gke-gcloud-auth-plugin
      provideClusterInfo: true
- name: gke_proj-b_eu-west1_cluster-b
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: /usr/lib/google-cloud-sdk/bin/gke-gcloud-auth-plugin
      provideClusterInfo: true
- name: custom-cluster
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: some-other-plugin
      provideClusterInfo: true
`;

// ---------------------------------------------------------------------------
// patchKubeconfig (pure function)
// ---------------------------------------------------------------------------

const FAKE_BINARY = "/usr/local/bin/gcp-authcalator";

describe("patchKubeconfig", () => {
  test("patches a single gke-gcloud-auth-plugin user", () => {
    const kubeconfig = parseYAML(SAMPLE_KUBECONFIG);
    const { patched, patchedUsers } = patchKubeconfig(kubeconfig, FAKE_BINARY);

    expect(patchedUsers).toEqual(["gke_my-project_us-central1_my-cluster"]);
    const exec = patched.users![0]!.user!.exec!;
    expect(exec.command).toBe(FAKE_BINARY);
    expect(exec.args).toEqual(["kube-token"]);
    expect(exec.apiVersion).toBe("client.authentication.k8s.io/v1beta1");
    expect(exec.provideClusterInfo).toBe(true);
    expect(exec.installHint).toContain("gcp-authcalator");
  });

  test("patches multiple users including full-path commands", () => {
    const kubeconfig = parseYAML(MULTI_USER_KUBECONFIG);
    const { patched, patchedUsers } = patchKubeconfig(kubeconfig, FAKE_BINARY);

    expect(patchedUsers).toEqual([
      "gke_proj-a_us-west1_cluster-a",
      "gke_proj-b_eu-west1_cluster-b",
    ]);

    // Both GKE entries patched
    expect(patched.users![0]!.user!.exec!.command).toBe(FAKE_BINARY);
    expect(patched.users![1]!.user!.exec!.command).toBe(FAKE_BINARY);

    // Non-GKE entry left alone
    expect(patched.users![2]!.user!.exec!.command).toBe("some-other-plugin");
  });

  test("returns empty patchedUsers when no gke-gcloud-auth-plugin entries exist", () => {
    const kubeconfig = {
      apiVersion: "v1",
      kind: "Config",
      users: [
        {
          name: "custom",
          user: { exec: { apiVersion: "v1beta1", command: "other-plugin" } },
        },
      ],
    };
    const { patchedUsers } = patchKubeconfig(kubeconfig, FAKE_BINARY);
    expect(patchedUsers).toEqual([]);
  });

  test("handles kubeconfig with no users array", () => {
    const kubeconfig = { apiVersion: "v1", kind: "Config" };
    const { patchedUsers } = patchKubeconfig(kubeconfig, FAKE_BINARY);
    expect(patchedUsers).toEqual([]);
  });

  test("handles users with no exec section", () => {
    const kubeconfig = {
      apiVersion: "v1",
      kind: "Config",
      users: [{ name: "token-user", user: { token: "static-token" } }],
    };
    const { patchedUsers } = patchKubeconfig(kubeconfig, FAKE_BINARY);
    expect(patchedUsers).toEqual([]);
  });

  test("removes env field from patched entries", () => {
    const kubeconfig = {
      apiVersion: "v1",
      kind: "Config",
      users: [
        {
          name: "gke-user",
          user: {
            exec: {
              apiVersion: "client.authentication.k8s.io/v1beta1",
              command: "gke-gcloud-auth-plugin",
              env: [{ name: "FOO", value: "bar" }],
            },
          },
        },
      ],
    };

    const { patched } = patchKubeconfig(kubeconfig, FAKE_BINARY);
    expect(patched.users![0]!.user!.exec!.env).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// runKubeSetup (integration — uses temp files)
// ---------------------------------------------------------------------------

describe("runKubeSetup", () => {
  let logSpy: ReturnType<typeof spyOn>;
  let warnSpy: ReturnType<typeof spyOn>;
  let errorSpy: ReturnType<typeof spyOn>;
  let exitSpy: ReturnType<typeof spyOn>;

  beforeEach(() => {
    logSpy = spyOn(console, "log").mockImplementation(() => {});
    warnSpy = spyOn(console, "warn").mockImplementation(() => {});
    errorSpy = spyOn(console, "error").mockImplementation(() => {});
    exitSpy = spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });
  });

  afterEach(() => {
    logSpy.mockRestore();
    warnSpy.mockRestore();
    errorSpy.mockRestore();
    exitSpy.mockRestore();
  });

  test("patches kubeconfig file and creates backup", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kube-setup-"));
    const kubeconfigPath = join(dir, "config");
    writeFileSync(kubeconfigPath, SAMPLE_KUBECONFIG);

    await runKubeSetup({ kubeconfigPath });

    // Verify the file was patched — command should be an absolute path
    const patched = parseYAML(readFileSync(kubeconfigPath, "utf-8"));
    const patchedCmd = patched.users[0].user.exec.command as string;
    expect(patchedCmd).toMatch(/^\//); // must be an absolute path
    expect(patched.users[0].user.exec.args).toEqual(["kube-token"]);

    // Verify backup was created
    const backup = readFileSync(`${kubeconfigPath}.bak`, "utf-8");
    expect(backup).toBe(SAMPLE_KUBECONFIG);

    // Verify log output
    const logOutput = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(logOutput).toContain("patched 1 user(s)");
    expect(logOutput).toContain("gke_my-project_us-central1_my-cluster");
    expect(logOutput).toContain("revert");
  });

  test("warns when no gke-gcloud-auth-plugin entries found", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kube-setup-"));
    const kubeconfigPath = join(dir, "config");
    writeFileSync(
      kubeconfigPath,
      `apiVersion: v1\nkind: Config\nusers:\n- name: other\n  user:\n    exec:\n      command: other-plugin\n`,
    );

    await runKubeSetup({ kubeconfigPath });

    const warnOutput = warnSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(warnOutput).toContain("no users with exec.command");
    expect(warnOutput).toContain("gke-gcloud-auth-plugin");
  });

  test("exits 1 when kubeconfig file does not exist", async () => {
    await expect(
      runKubeSetup({ kubeconfigPath: "/tmp/nonexistent-kube-setup-test" }),
    ).rejects.toThrow("process.exit called");

    expect(exitSpy).toHaveBeenCalledWith(1);
    const errorOutput = errorSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(errorOutput).toContain("failed to read kubeconfig");
  });

  test("preserves non-GKE users when patching", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kube-setup-"));
    const kubeconfigPath = join(dir, "config");
    writeFileSync(kubeconfigPath, MULTI_USER_KUBECONFIG);

    await runKubeSetup({ kubeconfigPath });

    const patched = parseYAML(readFileSync(kubeconfigPath, "utf-8"));
    expect(patched.users[0].user.exec.command as string).toMatch(/^\//);
    expect(patched.users[1].user.exec.command as string).toMatch(/^\//);
    expect(patched.users[2].user.exec.command).toBe("some-other-plugin");

    const logOutput = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(logOutput).toContain("patched 2 user(s)");
  });

  test("exits 1 when kubeconfig contains invalid YAML", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kube-setup-"));
    const kubeconfigPath = join(dir, "config");
    writeFileSync(kubeconfigPath, "{{{{not: valid: yaml: [[[");

    await expect(runKubeSetup({ kubeconfigPath })).rejects.toThrow("process.exit called");

    expect(exitSpy).toHaveBeenCalledWith(1);
    const errorOutput = errorSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(errorOutput).toContain("failed to parse kubeconfig YAML");
  });

  test("exits 1 when kubeconfig is empty", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kube-setup-"));
    const kubeconfigPath = join(dir, "config");
    writeFileSync(kubeconfigPath, "");

    await expect(runKubeSetup({ kubeconfigPath })).rejects.toThrow("process.exit called");

    expect(exitSpy).toHaveBeenCalledWith(1);
    const errorOutput = errorSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(errorOutput).toContain("empty or not a valid YAML");
  });

  test("exits 1 when kubeconfig is a scalar YAML value", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kube-setup-"));
    const kubeconfigPath = join(dir, "config");
    writeFileSync(kubeconfigPath, "just-a-string");

    await expect(runKubeSetup({ kubeconfigPath })).rejects.toThrow("process.exit called");

    expect(exitSpy).toHaveBeenCalledWith(1);
    const errorOutput = errorSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(errorOutput).toContain("empty or not a valid YAML");
  });

  test("uses KUBECONFIG env var when kubeconfigPath not provided", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kube-setup-"));
    const kubeconfigPath = join(dir, "custom-config");
    writeFileSync(kubeconfigPath, SAMPLE_KUBECONFIG);

    const originalKubeconfig = process.env.KUBECONFIG;
    process.env.KUBECONFIG = kubeconfigPath;

    try {
      await runKubeSetup({});

      // Verify the file was patched
      const patched = parseYAML(readFileSync(kubeconfigPath, "utf-8"));
      const patchedCmd = patched.users[0].user.exec.command as string;
      expect(patchedCmd).toMatch(/^\//);
    } finally {
      if (originalKubeconfig === undefined) {
        delete process.env.KUBECONFIG;
      } else {
        process.env.KUBECONFIG = originalKubeconfig;
      }
    }
  });

  test("uses first path from colon-separated KUBECONFIG", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kube-setup-"));
    const kubeconfigPath = join(dir, "first-config");
    writeFileSync(kubeconfigPath, SAMPLE_KUBECONFIG);

    const originalKubeconfig = process.env.KUBECONFIG;
    process.env.KUBECONFIG = `${kubeconfigPath}:/some/other/path`;

    try {
      await runKubeSetup({});

      const patched = parseYAML(readFileSync(kubeconfigPath, "utf-8"));
      const patchedCmd = patched.users[0].user.exec.command as string;
      expect(patchedCmd).toMatch(/^\//);
    } finally {
      if (originalKubeconfig === undefined) {
        delete process.env.KUBECONFIG;
      } else {
        process.env.KUBECONFIG = originalKubeconfig;
      }
    }
  });

  test("exits 1 when kubeconfig is not writable", async () => {
    const { chmodSync } = await import("node:fs");
    const dir = mkdtempSync(join(tmpdir(), "kube-setup-"));
    const kubeconfigPath = join(dir, "config");
    writeFileSync(kubeconfigPath, SAMPLE_KUBECONFIG);
    // Make the file read-only
    chmodSync(kubeconfigPath, 0o444);

    try {
      await expect(runKubeSetup({ kubeconfigPath })).rejects.toThrow("process.exit called");

      expect(exitSpy).toHaveBeenCalledWith(1);
      const errorOutput = errorSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
      expect(errorOutput).toContain("failed to write kubeconfig");
    } finally {
      // Restore write permission for cleanup
      chmodSync(kubeconfigPath, 0o644);
    }
  });

  test("dryRun mode does not write to disk", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kube-setup-"));
    const kubeconfigPath = join(dir, "config");
    writeFileSync(kubeconfigPath, SAMPLE_KUBECONFIG);

    await runKubeSetup({ kubeconfigPath, dryRun: true });

    // File should be unchanged
    const contents = readFileSync(kubeconfigPath, "utf-8");
    expect(contents).toBe(SAMPLE_KUBECONFIG);

    const logOutput = logSpy.mock.calls.map((c: unknown[]) => c[0]).join("\n");
    expect(logOutput).toContain("would patch 1 user(s)");
  });
});
