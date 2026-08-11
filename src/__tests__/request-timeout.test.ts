import { describe, expect, test } from "bun:test";
import { useApplicationDeadline } from "../request-timeout.ts";

describe("useApplicationDeadline", () => {
  test("disables Bun's per-request idle timeout", () => {
    const request = new Request("http://localhost/token");
    const calls: Array<[Request, number]> = [];
    const server = {
      timeout(req: Request, seconds: number) {
        calls.push([req, seconds]);
      },
    };

    useApplicationDeadline(request, server);

    expect(calls).toEqual([[request, 0]]);
  });
});
