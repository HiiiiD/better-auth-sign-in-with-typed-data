import type { InferOptionSchema } from "better-auth/types";

export const schema = {
	walletAddress: {
		fields: {
			userId: {
				type: "string",
				required: true,
				references: {
					model: "user",
					field: "id",
				},
			},
			address: {
				type: "string",
				required: true,
			},
			chainId: {
				type: "number",
				required: true,
			},
			isPrimary: {
				type: "boolean",
				required: true,
				defaultValue: false,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
} as const;

export type WalletAddressSchema = InferOptionSchema<typeof schema>;
