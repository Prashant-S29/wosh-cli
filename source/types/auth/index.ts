export type SignupData = {
	email: string;
	otp: string;
};

export type GetSessionResponse = {
	session: {
		expiresAt: string;
		token: string;
		createdAt: string;
		updatedAt: string;
		ipAddress: string;
		userAgent: string;
		userId: string;
		id: string;
	};
	user: {
		name: string;
		email: string;
		emailVerified: boolean;
		image: string | null;
		createdAt: string;
		updatedAt: string;
		id: string;
	};
};
