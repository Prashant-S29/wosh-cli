export type GetOrganizationResponse = {
	id: string;
	name: string;
	publicKey: string;
	requiredFactors: number;
	factorConfig: {
		requiredFactors: number;
		enabledFactors: ('passphrase' | 'device' | 'pin')[];
	};
	recoveryThreshold: number;
	createdAt: string;
	updatedAt: string;
};
