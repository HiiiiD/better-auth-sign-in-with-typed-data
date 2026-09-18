import { describe, expect, it } from "bun:test";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { memoryAdapter } from "@better-auth/memory-adapter";
import type { MemoryDB } from "@better-auth/memory-adapter";
import { privateKeyToAccount } from "viem/accounts";
import type { TypedData, TypedDataDomain } from "viem";
import { siwtd } from "./index";
import { siwtdClient } from "./client";

const PRIVATE_KEY =
	"0xdf859a20834dfe39a1a15b5b16550261e652010281c5529bfb967b24c1c107c4" as const;
const account = privateKeyToAccount(PRIVATE_KEY);

const TYPES = {
	Login: [
		{ name: "nonce", type: "string" },
		{ name: "issuedAt", type: "string" },
	],
} as const satisfies TypedData;

async function signLogin(opts: {
	domain: TypedDataDomain;
	nonce: string;
	issuedAt?: string;
}) {
	const message = {
		nonce: opts.nonce,
		issuedAt: opts.issuedAt ?? new Date().toISOString(),
	};
	const signature = await account.signTypedData({
		domain: opts.domain,
		types: TYPES,
		primaryType: "Login",
		message,
	});
	return {
		domain: opts.domain,
		types: TYPES,
		primaryType: "Login" as const,
		message,
		signature,
	};
}

function makeTestAuth() {
	const db: MemoryDB = {
		user: [],
		session: [],
		account: [],
		verification: [],
		walletAddress: [],
	};
	const auth = betterAuth({
		database: memoryAdapter(db),
		secret: "test-secret-at-least-32-characters-long",
		baseURL: "http://localhost:3000",
		plugins: [
			siwtd({
				domain: { name: "example.com", chainId: 1 },
				getNonce: async () => "A1b2C3d4E5f6G7h8",
			}),
		],
	});
	const client = createAuthClient({
		baseURL: "http://localhost:3000/api/auth",
		plugins: [siwtdClient()],
		fetchOptions: {
			customFetchImpl: async (input, init) =>
				auth.handler(new Request(input as string, init)),
		},
	});
	return { auth, client, db };
}

describe("siwtd nonce endpoint", () => {
	it("returns a nonce and stores a consumable verification record", async () => {
		const { client, db } = makeTestAuth();
		const { data } = await client.siwtd.nonce();
		expect(data?.nonce).toBe("A1b2C3d4E5f6G7h8");
		expect(
			db.verification?.some((v) => v.identifier === "siwtd:A1b2C3d4E5f6G7h8"),
		).toBe(true);
	});
});

describe("siwtd verify endpoint", () => {
	it("rejects when message.nonce is missing", async () => {
		const { client } = makeTestAuth();
		await client.siwtd.nonce();
		const { error } = await client.siwtd.verify({
			domain: { name: "example.com", chainId: 1 },
			types: TYPES,
			primaryType: "Login",
			message: { issuedAt: new Date().toISOString() },
			signature: "0xdead",
		} as any);
		expect(error?.status).toBe(400);
	});

	it("rejects an unknown or already-used nonce", async () => {
		const { client } = makeTestAuth();
		const payload = await signLogin({
			domain: { name: "example.com", chainId: 1 },
			nonce: "NeverIssuedNonce1",
		});
		const { error } = await client.siwtd.verify(payload);
		expect(error?.status).toBe(401);
		expect(error?.code).toBe("UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");
	});

	it("rejects a domain mismatch", async () => {
		const { client } = makeTestAuth();
		const { data: nonceData } = await client.siwtd.nonce();
		const payload = await signLogin({
			domain: { name: "wrong-domain.com", chainId: 1 },
			nonce: nonceData!.nonce,
		});
		const { error } = await client.siwtd.verify(payload);
		expect(error?.status).toBe(401);
		expect(error?.code).toBe("UNAUTHORIZED_DOMAIN_MISMATCH");
	});

	it("rejects a tampered signature", async () => {
		const { client } = makeTestAuth();
		const { data: nonceData } = await client.siwtd.nonce();
		const payload = await signLogin({
			domain: { name: "example.com", chainId: 1 },
			nonce: nonceData!.nonce,
		});
		payload.signature = `0x${"1".repeat(130)}` as `0x${string}`;
		const { error } = await client.siwtd.verify(payload);
		expect(error?.status).toBe(401);
		expect(error?.code).toBe("UNAUTHORIZED_INVALID_SIGNATURE");
	});
});
