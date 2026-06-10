/**
 * How far to backdate certificate `notBefore` timestamps. A few minutes of
 * margin absorbs small clock differences between the host that mints certs and
 * the client that validates them, so a slightly-ahead client clock doesn't
 * reject a freshly issued cert as "not yet valid".
 */
export const CLOCK_SKEW_MS = 5 * 60 * 1000;

/** notBefore for a freshly generated certificate, backdated for clock skew. */
export function certNotBefore(): Date {
  return new Date(Date.now() - CLOCK_SKEW_MS);
}

/** Generate a random serial number for X.509 certificates. */
export function randomSerialNumber(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  // Ensure positive by clearing high bit
  bytes[0]! &= 0x7f;
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Export a PKCS#8 private key as a PEM string. */
export function keyToPem(keyData: ArrayBuffer): string {
  const b64 = Buffer.from(keyData).toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----\n`;
}

/** Decode a PEM string into an ArrayBuffer. */
export function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/, "")
    .replace(/-----END [A-Z ]+-----/, "")
    .replace(/\s/g, "");
  return Buffer.from(b64, "base64").buffer as ArrayBuffer;
}
