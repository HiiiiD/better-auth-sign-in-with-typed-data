import { describe, expect, it } from "bun:test";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { memoryAdapter } from "@better-auth/memory-adapter";
import type { MemoryDB } from "@better-auth/memory-adapter";
import { privateKeyToAccount } from "viem/accounts";
import { siwtd } from "./index.js";
import { siwtdClient } from "./client.js";

interface SiwtdVerifyResponse {
	token: string;
	success: boolean;
	user: { id: string; walletAddress: string; chainId: number };
}

describe("siwtdClient round trip", () => {
	it("logs in end-to-end through the inferred client methods", async () => {
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
					domain: { name: "example.com" },
					getNonce: async () => "N0nc3ForClientTest1",
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

		const account = privateKeyToAccount(
			"0xdf859a20834dfe39a1a15b5b16550261e652010281c5529bfb967b24c1c107c4",
		);
		const { data: nonceData } = await client.siwtd.nonce();
		const types = {
			Login: [{ name: "nonce", type: "string" }],
		} as const;
		const message = { nonce: nonceData!.nonce };
		const signature = await account.signTypedData({
			domain: { name: "example.com", chainId: 1 },
			types,
			primaryType: "Login",
			message,
		});

		const { data: rawData, error } = await client.siwtd.verify({
			domain: { name: "example.com", chainId: 1 },
			types,
			primaryType: "Login",
			message,
			signature,
		});
		const data = rawData as unknown as SiwtdVerifyResponse | null;

		expect(error).toBeNull();
		expect(data?.success).toBe(true);
		expect(typeof data?.token).toBe("string");
	});
});
