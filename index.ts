import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { mergeSchema } from "better-auth/db";
import type { InferOptionSchema } from "better-auth/types";
import * as z from "zod";
import { schema, type WalletAddressSchema } from "./schema";
import type { ENSLookupArgs, ENSLookupResult } from "./types";

export interface SIWTDDomainOptions {
	name?: string;
	chainId?: number;
	verifyingContract?: `0x${string}`;
	version?: string;
}

export interface SIWTDPluginOptions {
	domain: SIWTDDomainOptions;
	getNonce: () => Promise<string>;
	ensLookup?: (args: ENSLookupArgs) => Promise<ENSLookupResult>;
	schema?: InferOptionSchema<typeof schema>;
}

const SIWTD_VERIFICATION_IDENTIFIER_PREFIX = "siwtd:";
const VERIFICATION_IDENTIFIER_MAX_LENGTH = 255;
const SIWTD_NONCE_MAX_LENGTH =
	VERIFICATION_IDENTIFIER_MAX_LENGTH -
	SIWTD_VERIFICATION_IDENTIFIER_PREFIX.length;
const SIWTD_NONCE_ALPHANUMERIC_REGEX = /^[a-zA-Z0-9]+$/;

const isValidSiwtdNonce = (nonce: string | undefined): nonce is string =>
	typeof nonce === "string" &&
	nonce.length >= 8 &&
	nonce.length <= SIWTD_NONCE_MAX_LENGTH &&
	SIWTD_NONCE_ALPHANUMERIC_REGEX.test(nonce);

const getSiwtdNonceBodySchema = z.object({}).strict().optional();

export const siwtd = (options: SIWTDPluginOptions) => {
	return {
		id: "siwtd",
		schema: mergeSchema(schema, options?.schema) as WalletAddressSchema,
		endpoints: {
			getSiwtdNonce: createAuthEndpoint(
				"/siwtd/nonce",
				{
					method: "POST",
					body: getSiwtdNonceBodySchema,
				},
				async (ctx) => {
					const nonce = await options.getNonce();
					if (!isValidSiwtdNonce(nonce)) {
						throw new APIError("INTERNAL_SERVER_ERROR", {
							message: `SIWTD getNonce must return 8-${SIWTD_NONCE_MAX_LENGTH} alphanumeric characters.`,
							code: "SIWTD_INVALID_NONCE",
						});
					}

					await ctx.context.internalAdapter.createVerificationValue({
						identifier: `${SIWTD_VERIFICATION_IDENTIFIER_PREFIX}${nonce}`,
						value: nonce,
						expiresAt: new Date(Date.now() + 15 * 60 * 1000),
					});

					return ctx.json({ nonce });
				},
			),
		},
	} satisfies BetterAuthPlugin;
};
