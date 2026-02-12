import { describe, expect, test } from "bun:test";
import { z } from "zod";
import { runMetadataProxy } from "../../commands/metadata-proxy.ts";

describe("runMetadataProxy", () => {
  test("throws ZodError when project_id is missing", async () => {
    await expect(
      runMetadataProxy({
        socket_path: "/tmp/gate.sock",
        port: 8173,
      }),
    ).rejects.toThrow(z.ZodError);
  });
});
