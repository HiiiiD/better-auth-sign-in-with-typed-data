import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthEndpoint, isAPIError } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { mergeSchema } from "better-auth/db";
import type { InferOptionSchema, User } from "better-auth/types";
import {
	getAddress,
	recoverTypedDataAddress,
	type Hex,
	type TypedData,
	type TypedDataDomain,
} from "viem";
import * as z from "zod";
import { schema, type WalletAddressSchema } from "./schema.js";
import type { ENSLookupArgs, ENSLookupResult, WalletAddress } from "./types.js";

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

const verifySiwtdBodySchema = z
	.object({
		domain: z.record(z.string(), z.any()),
		types: z.record(z.string(), z.any()),
		primaryType: z.string().min(1),
		message: z.record(z.string(), z.any()),
		signature: z.string().min(1),
	})
	.strict();

function domainMatches(
	expected: SIWTDDomainOptions,
	signed: TypedDataDomain,
): boolean {
	if (expected.name !== undefined && expected.name !== signed.name)
		return false;
	if (expected.chainId !== undefined && expected.chainId !== signed.chainId)
		return false;
	if (
		expected.verifyingContract !== undefined &&
		expected.verifyingContract.toLowerCase() !==
			(signed.verifyingContract as string | undefined)?.toLowerCase()
	)
		return false;
	if (expected.version !== undefined && expected.version !== signed.version)
		return false;
	return true;
}

function createPlaceholderEmail(address: string) {
	return `${address.toLowerCase()}@siwtd.invalid`;
}

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
			verifySiwtdMessage: createAuthEndpoint(
				"/siwtd/verify",
				{
					method: "POST",
					body: verifySiwtdBodySchema,
					requireRequest: true,
				},
				async (ctx) => {
					const { domain, types, primaryType, message, signature } = ctx.body;

					const nonce = message.nonce;
					if (typeof nonce !== "string" || !isValidSiwtdNonce(nonce)) {
						throw new APIError("BAD_REQUEST", {
							message: "message.nonce is required and must be a valid nonce.",
						});
					}

					try {
						const verification =
							await ctx.context.internalAdapter.consumeVerificationValue(
								`${SIWTD_VERIFICATION_IDENTIFIER_PREFIX}${nonce}`,
							);
						if (!verification) {
							throw new APIError("UNAUTHORIZED", {
								message: "Invalid or expired nonce",
								code: "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
							});
						}

						if (!domainMatches(options.domain, domain as TypedDataDomain)) {
							throw new APIError("UNAUTHORIZED", {
								message: "Signed domain does not match the expected domain",
								code: "UNAUTHORIZED_DOMAIN_MISMATCH",
							});
						}

						const signedChainId = (domain as TypedDataDomain).chainId;
						if (typeof signedChainId !== "number" || signedChainId <= 0) {
							throw new APIError("UNAUTHORIZED", {
								message: "Signed domain is missing a valid chainId",
								code: "UNAUTHORIZED_INVALID_CHAIN_ID",
							});
						}

						let recovered: `0x${string}`;
						try {
							recovered = await recoverTypedDataAddress({
								domain: domain as TypedDataDomain,
								types: types as TypedData,
								primaryType,
								message,
								signature: signature as Hex,
							});
						} catch {
							throw new APIError("UNAUTHORIZED", {
								message: "Invalid signature",
								code: "UNAUTHORIZED_INVALID_SIGNATURE",
							});
						}
						const walletAddress = getAddress(recovered);

						const expirationTime = message.expirationTime;
						const notBefore = message.notBefore;
						const now = Date.now();
						if (typeof expirationTime === "string") {
							const expiresAt = Date.parse(expirationTime);
							if (!Number.isNaN(expiresAt) && now >= expiresAt) {
								throw new APIError("UNAUTHORIZED", {
									message: "Message has expired",
									code: "UNAUTHORIZED_MESSAGE_EXPIRED",
								});
							}
						}
						if (typeof notBefore === "string") {
							const notBeforeAt = Date.parse(notBefore);
							if (!Number.isNaN(notBeforeAt) && now < notBeforeAt) {
								throw new APIError("UNAUTHORIZED", {
									message: "Message is not yet valid",
									code: "UNAUTHORIZED_MESSAGE_NOT_YET_VALID",
								});
							}
						}

						let user: User | null = null;

						const existingWalletAddress: WalletAddress | null =
							await ctx.context.adapter.findOne({
								model: "walletAddress",
								where: [
									{ field: "address", operator: "eq", value: walletAddress },
									{ field: "chainId", operator: "eq", value: signedChainId },
								],
							});

						if (existingWalletAddress) {
							user = await ctx.context.adapter.findOne({
								model: "user",
								where: [
									{
										field: "id",
										operator: "eq",
										value: existingWalletAddress.userId,
									},
								],
							});
						} else {
							const anyWalletAddress: WalletAddress | null =
								await ctx.context.adapter.findOne({
									model: "walletAddress",
									where: [
										{ field: "address", operator: "eq", value: walletAddress },
									],
								});
							if (anyWalletAddress) {
								user = await ctx.context.adapter.findOne({
									model: "user",
									where: [
										{
											field: "id",
											operator: "eq",
											value: anyWalletAddress.userId,
										},
									],
								});
							}
						}

						if (!user) {
							const { name, avatar } =
								(await options.ensLookup?.({ walletAddress })) ?? {};
							user = await ctx.context.internalAdapter.createUser(
								{
									name: name ?? walletAddress,
									email: createPlaceholderEmail(walletAddress),
									image: avatar ?? "",
								},
								{ method: "siwtd" },
							);

							await ctx.context.adapter.create({
								model: "walletAddress",
								data: {
									userId: user.id,
									address: walletAddress,
									chainId: signedChainId,
									isPrimary: true,
									createdAt: new Date(),
								},
							});

							await ctx.context.internalAdapter.createAccount({
								userId: user.id,
								providerId: "siwtd",
								accountId: `${walletAddress}:${signedChainId}`,
								createdAt: new Date(),
								updatedAt: new Date(),
							});
						} else if (!existingWalletAddress) {
							await ctx.context.adapter.create({
								model: "walletAddress",
								data: {
									userId: user.id,
									address: walletAddress,
									chainId: signedChainId,
									isPrimary: false,
									createdAt: new Date(),
								},
							});

							await ctx.context.internalAdapter.createAccount({
								userId: user.id,
								providerId: "siwtd",
								accountId: `${walletAddress}:${signedChainId}`,
								createdAt: new Date(),
								updatedAt: new Date(),
							});
						}

						const session = await ctx.context.internalAdapter.createSession(
							user.id,
						);
						if (!session) {
							throw new APIError("INTERNAL_SERVER_ERROR", {
								message: "Failed to create session",
							});
						}
						await setSessionCookie(ctx, { session, user });

						return ctx.json({
							token: session.token,
							success: true,
							user: {
								id: user.id,
								walletAddress,
								chainId: signedChainId,
							},
						});
					} catch (error: unknown) {
						if (isAPIError(error)) throw error;
						throw new APIError("UNAUTHORIZED", {
							message: "Something went wrong. Please try again later.",
						});
					}
				},
			),
		},
	} satisfies BetterAuthPlugin;
};
