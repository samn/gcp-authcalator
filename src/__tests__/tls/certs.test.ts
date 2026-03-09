import { describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { generateCA } from "../../tls/ca.ts";
import { generateServerCert, generateClientCert } from "../../tls/certs.ts";

describe("generateServerCert", () => {
  test("generates a valid server certificate", async () => {
    const ca = await generateCA();
    const { cert, key } = await generateServerCert(ca.caCert, ca.caKey);

    expect(cert).toContain("-----BEGIN CERTIFICATE-----");
    expect(key).toContain("-----BEGIN PRIVATE KEY-----");
  });

  test("server cert has correct subject", async () => {
    const ca = await generateCA();
    const { cert } = await generateServerCert(ca.caCert, ca.caKey);
    const x509Cert = new x509.X509Certificate(cert);

    expect(x509Cert.subject).toBe("CN=gcp-authcalator server");
  });

  test("server cert is signed by the CA (issuer matches CA subject)", async () => {
    const ca = await generateCA();
    const { cert } = await generateServerCert(ca.caCert, ca.caKey);
    const x509Cert = new x509.X509Certificate(cert);
    const caCert = new x509.X509Certificate(ca.caCert);

    expect(x509Cert.issuer).toBe(caCert.subject);
  });

  test("server cert signature is cryptographically valid against CA public key", async () => {
    const ca = await generateCA();
    const { cert } = await generateServerCert(ca.caCert, ca.caKey);
    const x509Cert = new x509.X509Certificate(cert);
    const caCert = new x509.X509Certificate(ca.caCert);

    const valid = await x509Cert.verify({ publicKey: await caCert.publicKey.export() });
    expect(valid).toBe(true);
  });

  test("server cert has SAN with localhost and 127.0.0.1", async () => {
    const ca = await generateCA();
    const { cert } = await generateServerCert(ca.caCert, ca.caKey);
    const x509Cert = new x509.X509Certificate(cert);

    const san = x509Cert.getExtension(x509.SubjectAlternativeNameExtension);
    expect(san).toBeDefined();

    const names = san!.names.toJSON();
    const dnsNames = names.filter((n) => n.type === "dns").map((n) => n.value);
    const ipNames = names.filter((n) => n.type === "ip").map((n) => n.value);

    expect(dnsNames).toContain("localhost");
    expect(ipNames).toContain("127.0.0.1");
  });

  test("server cert has serverAuth EKU", async () => {
    const ca = await generateCA();
    const { cert } = await generateServerCert(ca.caCert, ca.caKey);
    const x509Cert = new x509.X509Certificate(cert);

    const eku = x509Cert.getExtension(x509.ExtendedKeyUsageExtension);
    expect(eku).toBeDefined();
    // OID for serverAuth: 1.3.6.1.5.5.7.3.1
    expect(eku!.usages).toContain("1.3.6.1.5.5.7.3.1");
  });

  test("server cert has 90-day validity", async () => {
    const ca = await generateCA();
    const { cert } = await generateServerCert(ca.caCert, ca.caKey);
    const x509Cert = new x509.X509Certificate(cert);

    const validityMs = x509Cert.notAfter.getTime() - x509Cert.notBefore.getTime();
    const validityDays = validityMs / (24 * 60 * 60 * 1000);

    expect(validityDays).toBeGreaterThan(89);
    expect(validityDays).toBeLessThan(91);
  });

  test("server cert uses ECDSA P-256", async () => {
    const ca = await generateCA();
    const { cert } = await generateServerCert(ca.caCert, ca.caKey);
    const x509Cert = new x509.X509Certificate(cert);

    const alg = x509Cert.signatureAlgorithm as unknown as { name: string };
    expect(alg.name).toBe("ECDSA");
  });

  test("server cert has basicConstraints cA=false", async () => {
    const ca = await generateCA();
    const { cert } = await generateServerCert(ca.caCert, ca.caKey);
    const x509Cert = new x509.X509Certificate(cert);

    const bc = x509Cert.getExtension(x509.BasicConstraintsExtension);
    expect(bc).toBeDefined();
    expect(bc!.ca).toBe(false);
  });
});

describe("generateClientCert", () => {
  test("generates a valid client certificate", async () => {
    const ca = await generateCA();
    const { cert, key } = await generateClientCert(ca.caCert, ca.caKey);

    expect(cert).toContain("-----BEGIN CERTIFICATE-----");
    expect(key).toContain("-----BEGIN PRIVATE KEY-----");
  });

  test("client cert has correct subject", async () => {
    const ca = await generateCA();
    const { cert } = await generateClientCert(ca.caCert, ca.caKey);
    const x509Cert = new x509.X509Certificate(cert);

    expect(x509Cert.subject).toBe("CN=gcp-authcalator client");
  });

  test("client cert has clientAuth EKU", async () => {
    const ca = await generateCA();
    const { cert } = await generateClientCert(ca.caCert, ca.caKey);
    const x509Cert = new x509.X509Certificate(cert);

    const eku = x509Cert.getExtension(x509.ExtendedKeyUsageExtension);
    expect(eku).toBeDefined();
    // OID for clientAuth: 1.3.6.1.5.5.7.3.2
    expect(eku!.usages).toContain("1.3.6.1.5.5.7.3.2");
  });

  test("client cert has 90-day validity", async () => {
    const ca = await generateCA();
    const { cert } = await generateClientCert(ca.caCert, ca.caKey);
    const x509Cert = new x509.X509Certificate(cert);

    const validityMs = x509Cert.notAfter.getTime() - x509Cert.notBefore.getTime();
    const validityDays = validityMs / (24 * 60 * 60 * 1000);

    expect(validityDays).toBeGreaterThan(89);
    expect(validityDays).toBeLessThan(91);
  });

  test("client cert is signed by the CA", async () => {
    const ca = await generateCA();
    const { cert } = await generateClientCert(ca.caCert, ca.caKey);
    const x509Cert = new x509.X509Certificate(cert);
    const caCert = new x509.X509Certificate(ca.caCert);

    expect(x509Cert.issuer).toBe(caCert.subject);
  });

  test("client cert signature is cryptographically valid against CA public key", async () => {
    const ca = await generateCA();
    const { cert } = await generateClientCert(ca.caCert, ca.caKey);
    const x509Cert = new x509.X509Certificate(cert);
    const caCert = new x509.X509Certificate(ca.caCert);

    const valid = await x509Cert.verify({ publicKey: await caCert.publicKey.export() });
    expect(valid).toBe(true);
  });

  test("client cert uses ECDSA P-256", async () => {
    const ca = await generateCA();
    const { cert } = await generateClientCert(ca.caCert, ca.caKey);
    const x509Cert = new x509.X509Certificate(cert);

    const alg = x509Cert.signatureAlgorithm as unknown as { name: string };
    expect(alg.name).toBe("ECDSA");
  });
});
