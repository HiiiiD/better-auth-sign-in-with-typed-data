# better-auth-sign-in-with-typed-data (SIWTD)

A better-auth plugin for logging in by signing EIP-712 typed data, instead of
an ERC-4361 (SIWE) plain-text message. Works with any EVM-style secp256k1
wallet, including VeChain wallets (VeWorld, Sync2/Connex).

Unlike the official `siwe` plugin, the typed-data schema (domain/types/
message shape) is entirely up to you — the plugin only requires a `nonce`
field inside the signed `message`, and a `chainId` in the signed `domain`.
There is no email/password support: wallet address is the sole identity.

## Install

```bash
bun add better-auth-sign-in-with-typed-data viem
```

## Server

```ts
import { betterAuth } from "better-auth";
import { siwtd } from "better-auth-sign-in-with-typed-data";

export const auth = betterAuth({
  plugins: [
    siwtd({
      domain: { name: "my-app.example.com", chainId: 1 },
      getNonce: async () => crypto.randomUUID().replace(/-/g, ""),
    }),
  ],
});
```

## Client

```ts
import { createAuthClient } from "better-auth/client";
import { siwtdClient } from "better-auth-sign-in-with-typed-data/client";

export const authClient = createAuthClient({
  plugins: [siwtdClient()],
});

const { data: nonceData } = await authClient.siwtd.nonce();

const types = { Login: [{ name: "nonce", type: "string" }] } as const;
const message = { nonce: nonceData.nonce };
const domain = { name: "my-app.example.com", chainId: 1 };

const signature = await walletClient.signTypedData({
  domain,
  types,
  primaryType: "Login",
  message,
});

const { data } = await authClient.siwtd.verify({
  domain,
  types,
  primaryType: "Login",
  message,
  signature,
});
```

## Options

| Option | Required | Description |
| --- | --- | --- |
| `domain` | yes | EIP-712 domain fields to check against the signed typed data. Only the fields you set here are enforced (`name`, `chainId`, `verifyingContract`, `version`). |
| `getNonce` | yes | Returns a fresh nonce (8+ alphanumeric characters) for each `/siwtd/nonce` call. |
| `ensLookup` | no | Resolve a display `name`/`avatar` for a wallet address on first login. |
| `schema` | no | Override the `walletAddress` table schema. |

## How verification works

1. Client requests a nonce from `/siwtd/nonce`; the server stores it.
2. Client signs an EIP-712 typed-data payload of its own design, as long as
   the signed `message` includes that `nonce` and the signed `domain`
   includes a `chainId`.
3. Client submits `{ domain, types, primaryType, message, signature }` to
   `/siwtd/verify`.
4. The server atomically consumes the nonce (single use), checks the signed
   `domain` against the plugin's configured `domain` option, and recovers
   the signer's address from the signature via viem. The recovered address
   is the only trusted source of wallet identity — any address-shaped field
   inside `message` itself is ignored.
5. On success, the server finds or creates a `user` + `walletAddress` +
   `account` record for that address/chain, creates a session, and returns
   a session token.

## Testing

```bash
bun test
```

## Releasing

Versioning uses [changesets](https://github.com/changesets/changesets), but
nothing bumps automatically on every push to `master` — commits accumulate
until you're ready to cut a release:

1. On each PR that needs a release note, run `bunx changeset` and describe
   the change; commit the generated file under `.changeset/`.
2. When ready to release, manually run the `Version` workflow (Actions tab
   → Version → Run workflow). It bumps the version, updates the changelog
   from all pending changesets, commits straight to `master`, and pushes a
   `vX.Y.Z` tag.
3. The tag push triggers the `Publish` workflow, which builds and publishes
   to npm.
