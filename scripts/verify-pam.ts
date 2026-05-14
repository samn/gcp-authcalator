#!/usr/bin/env bun
// Verify PAM API quirks against a real entitlement.
//
// Three Phase-1 checks from the audit plan:
//   #2 — grants.search accepts a state filter (which expressions work?)
//   #1 — grants.revoke returns a long-running Operation pollable to done:true
//   #3 — Grant's createTime / updateTime / timeline.events relationship
//
// Usage:
//   # Read-only: only runs the search-filter probes (no grant creation).
//   bun scripts/verify-pam.ts projects/<project>/locations/<loc>/entitlements/<id>
//
//   # Full: also creates and revokes a short-lived grant to probe LRO + times.
//   bun scripts/verify-pam.ts --create-grant projects/<project>/locations/<loc>/entitlements/<id>
//
// Requires:
//   - gcloud installed and authenticated (`gcloud auth login`).
//   - The current ADC principal can read the entitlement (and, for
//     --create-grant, create a grant against it without manual approval).
//
// Safety: --create-grant elevates the current principal for the entitlement's
// minimum supported duration. The script revokes immediately and verifies
// the LRO completes; if the script crashes before revoke, the grant will
// linger until PAM expires it. Run only against entitlements where this
// blast radius is acceptable.

import { $ } from "bun";

const PAM_BASE = "https://privilegedaccessmanager.googleapis.com/v1";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function getAccessToken(): Promise<string> {
  const out = await $`gcloud auth print-access-token`.text();
  const token = out.trim();
  if (!token) throw new Error("gcloud auth print-access-token returned empty");
  return token;
}

interface FetchResult {
  status: number;
  statusText: string;
  body: unknown;
  rawBody: string;
}

async function pamFetch(token: string, url: string, init?: RequestInit): Promise<FetchResult> {
  const res = await fetch(url, {
    ...init,
    headers: {
      ...init?.headers,
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });
  const rawBody = await res.text();
  let body: unknown = rawBody;
  try {
    body = JSON.parse(rawBody);
  } catch {
    /* keep raw */
  }
  return { status: res.status, statusText: res.statusText, body, rawBody };
}

function logSection(title: string): void {
  console.log("\n" + "=".repeat(76));
  console.log(title);
  console.log("=".repeat(76));
}

function logSubsection(title: string): void {
  console.log("\n" + "-".repeat(60));
  console.log(title);
  console.log("-".repeat(60));
}

function summarize(result: FetchResult): string {
  if (typeof result.body === "object" && result.body !== null) {
    return JSON.stringify(result.body, null, 2);
  }
  return result.rawBody.length > 500
    ? `${result.rawBody.slice(0, 500)}...(truncated)`
    : result.rawBody;
}

async function sleep(ms: number): Promise<void> {
  await new Promise((r) => setTimeout(r, ms));
}

// ---------------------------------------------------------------------------
// Test #2: grants.search filter syntax
// ---------------------------------------------------------------------------

async function probeSearchFilters(token: string, entitlementPath: string): Promise<void> {
  logSection("Test #2 — grants.search filter syntax (deciding factor for replacing grants.list)");

  const baseSearchUrl = `${PAM_BASE}/${entitlementPath}/grants:search`;
  const callerRelationships = ["HAD_CREATED", "CAN_APPROVE"];

  // Baseline: search with no filter and each callerRelationship variant.
  for (const rel of callerRelationships) {
    logSubsection(`Baseline: callerRelationship=${rel} (no filter)`);
    const url = `${baseSearchUrl}?callerRelationship=${rel}`;
    const r = await pamFetch(token, url);
    console.log(`  GET ${url}`);
    console.log(`  -> ${r.status} ${r.statusText}`);
    const body = r.body as { grants?: unknown[]; nextPageToken?: string };
    if (r.status === 200 && Array.isArray(body.grants)) {
      console.log(`  grants returned: ${body.grants.length}`);
      const states = new Set<string>();
      for (const g of body.grants) {
        const s = (g as { state?: string }).state;
        if (typeof s === "string") states.add(s);
      }
      console.log(`  states observed: ${[...states].join(", ") || "(none)"}`);
    } else {
      console.log(`  body: ${summarize(r).slice(0, 400)}`);
    }
  }

  // Filter expressions to try. Goal: find one that returns only active grants
  // for grants the caller created.
  const filters = [
    "state=ACTIVE",
    'state="ACTIVE"',
    "state:ACTIVE",
    "state = ACTIVE",
    "state=ACTIVATED",
    "state=ACTIVE OR state=ACTIVATED",
    'state="ACTIVE" OR state="ACTIVATED"',
  ];

  logSubsection("Filtered searches (callerRelationship=HAD_CREATED)");
  for (const filter of filters) {
    const url = `${baseSearchUrl}?callerRelationship=HAD_CREATED&filter=${encodeURIComponent(filter)}`;
    const r = await pamFetch(token, url);
    console.log(`\n  filter=${JSON.stringify(filter)}`);
    console.log(`  -> ${r.status} ${r.statusText}`);
    if (r.status === 200) {
      const body = r.body as { grants?: unknown[] };
      const grantsLen = Array.isArray(body.grants) ? body.grants.length : 0;
      console.log(`  grants returned: ${grantsLen}`);
      if (Array.isArray(body.grants)) {
        const states = new Set<string>();
        for (const g of body.grants) {
          const s = (g as { state?: string }).state;
          if (typeof s === "string") states.add(s);
        }
        console.log(`  states observed: ${[...states].join(", ") || "(none)"}`);
        console.log(
          `  PASS — server accepted this filter. Use this expression in pam.ts:scanForOpenGrants.`,
        );
      }
    } else {
      const err = (r.body as { error?: { message?: string; status?: string } }).error;
      console.log(`  body: ${err?.status ?? "?"} — ${err?.message ?? r.rawBody.slice(0, 200)}`);
    }
  }

  // Also try the same filters on the documented but undocumented-syntax
  // grants.list endpoint, so we can confirm the prior comment in pam.ts:269
  // about "every filter we've tried fails" is still current.
  logSubsection("Cross-check: grants.list with the same filter expressions");
  const baseListUrl = `${PAM_BASE}/${entitlementPath}/grants`;
  for (const filter of filters) {
    const url = `${baseListUrl}?pageSize=10&filter=${encodeURIComponent(filter)}`;
    const r = await pamFetch(token, url);
    console.log(`\n  filter=${JSON.stringify(filter)}`);
    console.log(`  -> ${r.status} ${r.statusText}`);
    if (r.status === 200) {
      const body = r.body as { grants?: unknown[] };
      console.log(
        `  grants returned: ${Array.isArray(body.grants) ? body.grants.length : "(none)"}`,
      );
    } else {
      const err = (r.body as { error?: { message?: string; status?: string } }).error;
      console.log(`  ${err?.status ?? "?"} — ${err?.message ?? r.rawBody.slice(0, 200)}`);
    }
  }

  // Also check orderBy support (a documented list parameter that, if it
  // works, lets us push the open grant onto page 1 in the fallback path).
  logSubsection("Cross-check: grants.list with orderBy=createTime desc");
  const orderByUrl = `${baseListUrl}?pageSize=5&orderBy=${encodeURIComponent("createTime desc")}`;
  const orderR = await pamFetch(token, orderByUrl);
  console.log(`  GET ${orderByUrl}`);
  console.log(`  -> ${orderR.status} ${orderR.statusText}`);
  if (orderR.status !== 200) {
    const err = (orderR.body as { error?: { message?: string; status?: string } }).error;
    console.log(`  ${err?.status ?? "?"} — ${err?.message ?? orderR.rawBody.slice(0, 200)}`);
  } else {
    const body = orderR.body as { grants?: Array<{ name?: string; createTime?: string }> };
    if (Array.isArray(body.grants)) {
      console.log(`  Top ${body.grants.length} grants by createTime desc:`);
      for (const g of body.grants) {
        console.log(`    ${g.createTime ?? "(no createTime)"} — ${g.name ?? "(no name)"}`);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Tests #1 + #3: create + revoke a short-lived grant
// ---------------------------------------------------------------------------

async function probeLroAndTimes(
  token: string,
  entitlementPath: string,
  durationSeconds: number,
): Promise<void> {
  logSection("Test #1 + #3 — create grant, inspect time fields, revoke as LRO");

  const createUrl = `${PAM_BASE}/${entitlementPath}/grants`;
  const createBody = {
    requestedDuration: `${durationSeconds}s`,
    justification: { unstructuredJustification: "gcp-authcalator verify-pam script" },
  };

  logSubsection(`Creating grant (duration=${durationSeconds}s)`);
  const createR = await pamFetch(token, createUrl, {
    method: "POST",
    body: JSON.stringify(createBody),
  });
  console.log(`  POST ${createUrl}`);
  console.log(`  -> ${createR.status} ${createR.statusText}`);

  if (createR.status !== 200) {
    console.log(`  Create failed; cannot run LRO/time probes:\n${summarize(createR)}`);
    console.log(
      "\n  HINT: if PAM rejects the duration, re-run with --duration-seconds <N> (e.g. 1860).",
    );
    return;
  }

  const grant = createR.body as {
    name?: string;
    state?: string;
    createTime?: string;
    updateTime?: string;
    requestedDuration?: string;
    timeline?: { events?: Array<Record<string, unknown>> };
  };
  console.log(`  grant.name = ${grant.name}`);
  console.log(`  grant.state = ${grant.state}`);

  if (!grant.name) {
    console.log("  No grant.name in response — aborting further probes.");
    return;
  }

  // Test #3: dump time fields and timeline.
  logSubsection("Test #3 — Grant time fields");
  console.log(`  createTime = ${grant.createTime}`);
  console.log(`  updateTime = ${grant.updateTime}`);
  console.log(`  requestedDuration = ${grant.requestedDuration}`);
  console.log(`  timeline.events:`);
  if (Array.isArray(grant.timeline?.events)) {
    for (const ev of grant.timeline.events) {
      console.log(`    ${JSON.stringify(ev)}`);
    }
  } else {
    console.log(`    (none)`);
  }

  // If grant isn't active yet, poll briefly.
  let active = grant.state === "ACTIVE" || grant.state === "ACTIVATED";
  let polls = 0;
  while (!active && polls < 30) {
    polls++;
    await sleep(1000);
    const getR = await pamFetch(token, `${PAM_BASE}/${grant.name}`);
    const g = getR.body as { state?: string; timeline?: { events?: Array<unknown> } };
    if (g.state === "ACTIVE" || g.state === "ACTIVATED") {
      active = true;
      console.log(`  Activated after ${polls}s. state=${g.state}`);
      console.log(`  Post-activation timeline.events:`);
      if (Array.isArray(g.timeline?.events)) {
        for (const ev of g.timeline.events) {
          console.log(`    ${JSON.stringify(ev)}`);
        }
      }
    } else {
      console.log(`  poll ${polls}: state=${g.state}`);
    }
  }
  if (!active) {
    console.log("  Grant didn't activate within 30s — entitlement may require approval.");
    console.log("  Attempting revoke anyway to clean up.");
  }

  // Re-run the filter probes now that an active grant exists, so we can
  // confirm which filter expression actually returns the active grant.
  if (active) {
    logSubsection("Test #2 re-check — search with active grant present");
    const baseSearchUrl = `${PAM_BASE}/${entitlementPath}/grants:search`;
    const filters = ['state="ACTIVE"', "state:ACTIVE", 'state="ACTIVATED"', "state:ACTIVATED"];
    for (const filter of filters) {
      const url = `${baseSearchUrl}?callerRelationship=HAD_CREATED&filter=${encodeURIComponent(filter)}`;
      const r = await pamFetch(token, url);
      console.log(`\n  filter=${JSON.stringify(filter)}`);
      console.log(`  -> ${r.status} ${r.statusText}`);
      if (r.status === 200) {
        const body = r.body as { grants?: Array<{ name?: string; state?: string }> };
        const grantsArr = Array.isArray(body.grants) ? body.grants : [];
        console.log(`  grants returned: ${grantsArr.length}`);
        for (const g of grantsArr) {
          console.log(`    state=${g.state}, name=${g.name}`);
        }
        if (grantsArr.some((g) => g.name === grant.name)) {
          console.log(`  PASS — filter returned our active grant.`);
        }
      } else {
        const err = (r.body as { error?: { message?: string } }).error;
        console.log(`  body: ${err?.message ?? r.rawBody.slice(0, 200)}`);
      }
    }

    logSubsection("Test #2 re-check — grants.list with active grant present");
    const baseListUrl = `${PAM_BASE}/${entitlementPath}/grants`;
    for (const filter of filters) {
      const url = `${baseListUrl}?pageSize=10&filter=${encodeURIComponent(filter)}`;
      const r = await pamFetch(token, url);
      console.log(`\n  filter=${JSON.stringify(filter)}`);
      console.log(`  -> ${r.status} ${r.statusText}`);
      if (r.status === 200) {
        const body = r.body as { grants?: Array<{ name?: string; state?: string }> };
        const grantsArr = Array.isArray(body.grants) ? body.grants : [];
        console.log(`  grants returned: ${grantsArr.length}`);
        for (const g of grantsArr) {
          console.log(`    state=${g.state}, name=${g.name}`);
        }
      }
    }
  }

  // Test #1: revoke and confirm LRO.
  logSubsection("Test #1 — grants.revoke Operation shape and pollability");
  const revokeUrl = `${PAM_BASE}/${grant.name}:revoke`;
  const revokeStart = Date.now();
  const revokeR = await pamFetch(token, revokeUrl, {
    method: "POST",
    body: JSON.stringify({ reason: "verify-pam script cleanup" }),
  });
  console.log(`  POST ${revokeUrl}`);
  console.log(`  -> ${revokeR.status} ${revokeR.statusText}`);
  if (revokeR.status !== 200) {
    console.log(`  Revoke failed:\n${summarize(revokeR)}`);
    return;
  }
  console.log(`  Revoke response body:\n${summarize(revokeR)}`);

  const op = revokeR.body as { name?: string; done?: boolean; error?: unknown };
  if (op.done === true) {
    console.log("  Operation completed synchronously (done:true in initial response).");
  } else if (!op.name) {
    console.log("  Response has no operation name — can't poll. Treat as best-effort.");
  } else {
    console.log(`  Polling operation ${op.name}...`);
    let attempts = 0;
    while (attempts < 60) {
      attempts++;
      await sleep(500);
      const pollR = await pamFetch(token, `${PAM_BASE}/${op.name}`);
      const polled = pollR.body as { done?: boolean; error?: unknown };
      if (polled.done) {
        const elapsed = Date.now() - revokeStart;
        console.log(`  Operation done after ${elapsed}ms (${attempts} polls).`);
        console.log(`  Final body:\n${summarize(pollR)}`);
        break;
      }
      if (attempts % 5 === 0) {
        console.log(`  poll ${attempts}: still not done`);
      }
    }
  }

  // Try create again to see if PAM has "released" the entitlement.
  logSubsection("Post-revoke: can we immediately create again?");
  const create2R = await pamFetch(token, createUrl, {
    method: "POST",
    body: JSON.stringify(createBody),
  });
  console.log(`  POST ${createUrl}`);
  console.log(`  -> ${create2R.status} ${create2R.statusText}`);
  if (create2R.status === 200) {
    const g2 = create2R.body as { name?: string };
    console.log(`  Success. grant.name = ${g2.name}`);
    // Clean up: revoke the new one too.
    if (g2.name) {
      const cleanupR = await pamFetch(token, `${PAM_BASE}/${g2.name}:revoke`, {
        method: "POST",
        body: JSON.stringify({ reason: "verify-pam script cleanup #2" }),
      });
      console.log(`  cleanup revoke -> ${cleanupR.status} ${cleanupR.statusText}`);
    }
  } else {
    console.log(`  body: ${summarize(create2R)}`);
    console.log(
      "  If this is 400 FAILED_PRECONDITION 'open Grant' or 409, the LRO race exists in practice.",
    );
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function parseFlag(args: string[], name: string): string | undefined {
  const idx = args.findIndex((a) => a === name || a.startsWith(`${name}=`));
  if (idx < 0) return undefined;
  const arg = args[idx]!;
  if (arg.includes("=")) return arg.split("=", 2)[1];
  return args[idx + 1];
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const createGrant = args.includes("--create-grant");
  const durationArg = parseFlag(args, "--duration-seconds");
  const durationSeconds = durationArg ? Number(durationArg) : 1860; // 31 min default
  const positional = args.filter((a) => !a.startsWith("--") && !/^\d+$/.test(a));
  const entitlementPath = positional[0];

  if (!entitlementPath) {
    console.error(
      "Usage: bun scripts/verify-pam.ts [--create-grant] [--duration-seconds N] " +
        "projects/<p>/locations/<l>/entitlements/<id>",
    );
    process.exit(2);
  }

  if (!/^projects\/[^/]+\/locations\/[^/]+\/entitlements\/[^/]+$/.test(entitlementPath)) {
    console.error(`Invalid entitlement path: ${entitlementPath}`);
    process.exit(2);
  }

  if (Number.isNaN(durationSeconds) || durationSeconds <= 0) {
    console.error(`Invalid --duration-seconds: ${durationArg}`);
    process.exit(2);
  }

  console.log(`Entitlement: ${entitlementPath}`);
  console.log(
    `Mode: ${createGrant ? `FULL (creates real grant for ${durationSeconds}s)` : "read-only"}`,
  );

  const token = await getAccessToken();
  console.log(`Token obtained (length ${token.length}).`);

  await probeSearchFilters(token, entitlementPath);

  if (createGrant) {
    await probeLroAndTimes(token, entitlementPath, durationSeconds);
  } else {
    logSection("Skipped — tests #1 (LRO) and #3 (times) require --create-grant");
    console.log(
      "Pass --create-grant to enable; the script will create + revoke a short-lived grant.",
    );
  }

  console.log("\nDone.");
}

await main();
