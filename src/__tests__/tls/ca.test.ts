import { describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { generateCA } from "../../tls/ca.ts";

describe("generateCA", () => {
  test("generates a valid self-signed CA certificate", async () => {
    const { caCert, caKey } = await generateCA();

    expect(caCert).toContain("-----BEGIN CERTIFICATE-----");
    expect(caCert).toContain("-----END CERTIFICATE-----");
    expect(caKey).toContain("-----BEGIN PRIVATE KEY-----");
    expect(caKey).toContain("-----END PRIVATE KEY-----");
  });

  test("CA cert has correct subject", async () => {
    const { caCert } = await generateCA();
    const cert = new x509.X509Certificate(caCert);

    expect(cert.subject).toBe("CN=gcp-authcalator CA");
  });

  test("CA cert is self-signed (issuer matches subject)", async () => {
    const { caCert } = await generateCA();
    const cert = new x509.X509Certificate(caCert);

    expect(cert.issuer).toBe(cert.subject);
  });

  test("CA cert has 1-year validity", async () => {
    const { caCert } = await generateCA();
    const cert = new x509.X509Certificate(caCert);

    const validityMs = cert.notAfter.getTime() - cert.notBefore.getTime();
    const validityDays = validityMs / (24 * 60 * 60 * 1000);

    // Allow 1 day tolerance
    expect(validityDays).toBeGreaterThan(364);
    expect(validityDays).toBeLessThan(366);
  });

  test("CA cert has basicConstraints with cA=true", async () => {
    const { caCert } = await generateCA();
    const cert = new x509.X509Certificate(caCert);

    const bc = cert.getExtension(x509.BasicConstraintsExtension);
    expect(bc).toBeDefined();
    expect(bc!.ca).toBe(true);
  });

  test("CA cert has keyUsage with keyCertSign and cRLSign", async () => {
    const { caCert } = await generateCA();
    const cert = new x509.X509Certificate(caCert);

    const ku = cert.getExtension(x509.KeyUsagesExtension);
    expect(ku).toBeDefined();
    expect(ku!.usages & x509.KeyUsageFlags.keyCertSign).toBeTruthy();
    expect(ku!.usages & x509.KeyUsageFlags.cRLSign).toBeTruthy();
  });

  test("CA cert uses ECDSA P-256", async () => {
    const { caCert } = await generateCA();
    const cert = new x509.X509Certificate(caCert);

    const alg = cert.signatureAlgorithm as unknown as { name: string };
    expect(alg.name).toBe("ECDSA");
  });

  test("generates unique serial numbers on each call", async () => {
    const ca1 = await generateCA();
    const ca2 = await generateCA();
    const cert1 = new x509.X509Certificate(ca1.caCert);
    const cert2 = new x509.X509Certificate(ca2.caCert);

    expect(cert1.serialNumber).not.toBe(cert2.serialNumber);
  });
});
