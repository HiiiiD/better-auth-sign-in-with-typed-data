import { describe, expect, it } from "bun:test";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { memoryAdapter } from "@better-auth/memory-adapter";
import type { MemoryDB } from "@better-auth/memory-adapter";
import { siwtd } from "./index";
import { siwtdClient } from "./client";

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
