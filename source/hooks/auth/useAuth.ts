import {GetSessionResponse} from '../../types/auth/index.js';
import {
	getSessionToken,
	getSessionTokenData,
	removeSessionToken,
} from '../../utils/token/utils.sessionToken.js';

/**
 * Check authentication status for CLI
 * Checks if token exists, validates it with backend, and returns auth status
 */
export const useAuth = async () => {
	try {
		// Step 1: Check if token exists locally
		const storedToken = await getSessionToken();

		if (!storedToken) {
			return {
				isAuthenticated: false,
				token: null,
				session: null,
				error: null,
			};
		}

		// Step 2: Verify token with backend
		const sessionResponse = await getSessionTokenData();

		// Step 3: Check if session data exists
		if (sessionResponse.error || !sessionResponse.data?.session?.id) {
			// Token is invalid or expired, remove it
			removeSessionToken();
			return {
				isAuthenticated: false,
				token: null,
				session: null,
				error: sessionResponse.error || 'Invalid session',
			};
		}

		// Step 4: All good, user is authenticated
		return {
			isAuthenticated: true,
			token: storedToken,
			session: sessionResponse.data,
			error: null,
		};
	} catch (error) {
		console.error('Auth check error:', error);
		return {
			isAuthenticated: false,
			token: null,
			session: null,
			error: error instanceof Error ? error.message : 'Unknown error',
		};
	}
};

/**
 * Get user session data (when already authenticated)
 */
export const getSession = async (): Promise<GetSessionResponse | null> => {
	const authResult = await useAuth();
	return authResult.session;
};

/**
 * Check if user is authenticated (simple boolean check)
 */
export const isAuthenticated = async (): Promise<boolean> => {
	const authResult = await useAuth();
	return authResult.isAuthenticated;
};
