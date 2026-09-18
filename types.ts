export interface WalletAddress {
	id: string;
	userId: string;
	address: string;
	chainId: number;
	isPrimary: boolean;
	createdAt: Date;
}

export interface ENSLookupArgs {
	walletAddress: string;
}

export interface ENSLookupResult {
	name?: string;
	avatar?: string;
}
