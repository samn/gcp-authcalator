import * as x509 from "@peculiar/x509";

/**
 * Generate a server certificate signed by the given CA.
 *
 * - SAN: localhost, 127.0.0.1
 * - EKU: serverAuth
 * - Validity: 90 days
 * - ECDSA P-256
 */
export async function generateServerCert(
  caCert: string,
  caKey: string,
): Promise<{ cert: string; key: string }> {
  const algorithm = { name: "ECDSA", namedCurve: "P-256" };
  const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);

  const caKeyObj = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(caKey),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const caCertObj = new x509.X509Certificate(caCert);

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: randomSerialNumber(),
    subject: "CN=gcp-authcalator server",
    issuer: caCertObj.subject,
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days
    publicKey: keys.publicKey,
    signingKey: caKeyObj,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.ExtendedKeyUsageExtension(["1.3.6.1.5.5.7.3.1"], true), // serverAuth
      new x509.SubjectAlternativeNameExtension([
        { type: "dns", value: "localhost" },
        { type: "ip", value: "127.0.0.1" },
      ]),
    ],
  });

  const exportedKey = await crypto.subtle.exportKey("pkcs8", keys.privateKey);

  return {
    cert: cert.toString("pem"),
    key: keyToPem(exportedKey),
  };
}

/**
 * Generate a client certificate signed by the given CA.
 *
 * - EKU: clientAuth
 * - Validity: 90 days
 * - ECDSA P-256
 */
export async function generateClientCert(
  caCert: string,
  caKey: string,
): Promise<{ cert: string; key: string }> {
  const algorithm = { name: "ECDSA", namedCurve: "P-256" };
  const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);

  const caKeyObj = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(caKey),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const caCertObj = new x509.X509Certificate(caCert);

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: randomSerialNumber(),
    subject: "CN=gcp-authcalator client",
    issuer: caCertObj.subject,
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days
    publicKey: keys.publicKey,
    signingKey: caKeyObj,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.ExtendedKeyUsageExtension(["1.3.6.1.5.5.7.3.2"], true), // clientAuth
    ],
  });

  const exportedKey = await crypto.subtle.exportKey("pkcs8", keys.privateKey);

  return {
    cert: cert.toString("pem"),
    key: keyToPem(exportedKey),
  };
}

function randomSerialNumber(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[0]! &= 0x7f;
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function keyToPem(keyData: ArrayBuffer): string {
  const b64 = Buffer.from(keyData).toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----\n`;
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/, "")
    .replace(/-----END [A-Z ]+-----/, "")
    .replace(/\s/g, "");
  return Buffer.from(b64, "base64").buffer as ArrayBuffer;
}
