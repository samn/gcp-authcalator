import * as x509 from "@peculiar/x509";
import { randomSerialNumber, keyToPem } from "./utils.ts";

/**
 * Generate a self-signed CA certificate with an ECDSA P-256 keypair.
 *
 * The CA is used to sign server and client certificates for mTLS
 * communication between gate and remote metadata-proxy / with-prod.
 */
export async function generateCA(): Promise<{ caCert: string; caKey: string }> {
  const algorithm = { name: "ECDSA", namedCurve: "P-256" };

  const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomSerialNumber(),
    name: "CN=gcp-authcalator CA",
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days
    keys,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });

  const exportedKey = await crypto.subtle.exportKey("pkcs8", keys.privateKey);

  return {
    caCert: cert.toString("pem"),
    caKey: keyToPem(exportedKey),
  };
}
