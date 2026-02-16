# Implement `/computeMetadata/v1/instance/service-accounts` Endpoint

## Context

The real GCE metadata server exposes `/computeMetadata/v1/instance/service-accounts/` as a directory listing of available service accounts. Currently the proxy handles paths _under_ `service-accounts/default/` but not the listing endpoint itself. Some GCP client libraries query this endpoint to discover available service accounts.

## Changes

### 1. Add handler in `[src/metadata-proxy/handlers.ts](src/metadata-proxy/handlers.ts)`

Add a new case to the `switch` statement (before the `default` case, around line 71):

```typescript
case "/computeMetadata/v1/instance/service-accounts":
  return handleServiceAccounts(url, deps);
```

Add a new handler function `handleServiceAccounts`:

- **Non-recursive** (default): return plain text `"default/\n"` (matches real GCE format -- directory entries end with `/`)
- **`?recursive=true`**: return JSON with the service account info keyed by `"default"`, mirroring real GCE behavior:

```typescript
function handleServiceAccounts(url: URL, deps: MetadataProxyDeps): Response {
  const recursive = url.searchParams.get("recursive") === "true";

  if (recursive) {
    return jsonResponse({
      default: {
        aliases: ["default"],
        email: deps.serviceAccountEmail ?? "default",
        scopes: ["https://www.googleapis.com/auth/cloud-platform"],
      },
    });
  }

  return textResponse("default/\n");
}
```

### 2. Update startup log in `[src/metadata-proxy/server.ts](src/metadata-proxy/server.ts)`

Add the new endpoint to the console output in the startup log block (around line 107) so operators can see it listed.

### 3. Add tests in `[src/__tests__/metadata-proxy/handlers.test.ts](src/__tests__/metadata-proxy/handlers.test.ts)`

Follow the existing test patterns (`describe` block, `metadataRequest` helper, `makeDeps`). Tests to add:

- Returns plain text `"default/\n"` for non-recursive request
- Returns JSON with `default` key and service account info for `?recursive=true`
- Uses configured `serviceAccountEmail` in recursive response
- Falls back to `"default"` when `serviceAccountEmail` is undefined in recursive response
- Works with and without trailing slash
- Returns `Metadata-Flavor: Google` header

### 4. Update `[GOAL.md](GOAL.md)`

Add the new endpoint to the metadata proxy endpoints section (around line 107) to keep the documentation current.

### 5. Save plan to `plans/`

Save this plan as `plans/service-accounts-endpoint.md`.
