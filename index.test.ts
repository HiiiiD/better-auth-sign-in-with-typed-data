import { describe, expect, it } from "bun:test";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { memoryAdapter } from "@better-auth/memory-adapter";
import type { MemoryDB } from "@better-auth/memory-adapter";
import { privateKeyToAccount } from "viem/accounts";
import type { TypedData, TypedDataDomain } from "viem";
import { siwtd } from "./index.js";
import { siwtdClient } from "./client.js";

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
	let nonceCounter = 0;
	const auth = betterAuth({
		database: memoryAdapter(db),
		secret: "test-secret-at-least-32-characters-long",
		baseURL: "http://localhost:3000",
		plugins: [
			siwtd({
				domain: { name: "example.com" },
				getNonce: async () => `A1b2C3d4E5f6G7h8${nonceCounter++}`,
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
		expect(data?.nonce).toBe("A1b2C3d4E5f6G7h80");
		expect(
			db.verification?.some((v) => v.identifier === `siwtd:${data?.nonce}`),
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

interface SiwtdVerifyResponse {
	token: string;
	success: boolean;
	user: { id: string; walletAddress: string; chainId: number };
}

describe("siwtd verify endpoint — user linking", () => {
	it("creates a new user and wallet address on first login", async () => {
		const { client, db } = makeTestAuth();
		const { data: nonceData } = await client.siwtd.nonce();
		const payload = await signLogin({
			domain: { name: "example.com", chainId: 1 },
			nonce: nonceData!.nonce,
		});
		const { data: rawData, error } = await client.siwtd.verify(payload);
		const data = rawData as unknown as SiwtdVerifyResponse | null;
		expect(error).toBeNull();
		expect(data?.success).toBe(true);
		expect(data?.user.walletAddress.toLowerCase()).toBe(
			account.address.toLowerCase(),
		);
		expect(db.user?.length).toBe(1);
		expect(db.walletAddress?.length).toBe(1);
		expect(db.walletAddress?.[0]?.isPrimary).toBe(true);
	});

	it("logs into the existing user on the same address+chain", async () => {
		const { client, db } = makeTestAuth();
		const { data: nonce1 } = await client.siwtd.nonce();
		await client.siwtd.verify(
			await signLogin({
				domain: { name: "example.com", chainId: 1 },
				nonce: nonce1!.nonce,
			}),
		);
		const { data: nonce2 } = await client.siwtd.nonce();
		const { data: rawData } = await client.siwtd.verify(
			await signLogin({
				domain: { name: "example.com", chainId: 1 },
				nonce: nonce2!.nonce,
			}),
		);
		const data = rawData as unknown as SiwtdVerifyResponse | null;
		expect(db.user?.length).toBe(1);
		expect(db.walletAddress?.length).toBe(1);
		expect(data?.user.id).toBe(db.user?.[0]?.id);
	});

	it("adds a new walletAddress for the same user on a different chain", async () => {
		const { client, db } = makeTestAuth();
		const { data: nonce1 } = await client.siwtd.nonce();
		await client.siwtd.verify(
			await signLogin({
				domain: { name: "example.com", chainId: 1 },
				nonce: nonce1!.nonce,
			}),
		);
		const { data: nonce2 } = await client.siwtd.nonce();
		await client.siwtd.verify(
			await signLogin({
				domain: { name: "example.com", chainId: 100 },
				nonce: nonce2!.nonce,
			}),
		);
		expect(db.user?.length).toBe(1);
		expect(db.walletAddress?.length).toBe(2);
		expect(db.walletAddress?.[1]?.isPrimary).toBe(false);
	});
});
