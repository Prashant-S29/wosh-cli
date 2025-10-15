import {GetSessionResponse} from '../../types/auth/index.js';
import {getToken, removeToken} from '../../utils/utils.token.js';

// Type definitions (match your backend response)

/**
 * Verify session with backend API
 */
const verifySession = async (token: string) => {
	try {
		const response = await fetch(
			`${process.env['BACKEND_BASE_URL']}/api/auth/session`,
			{
				method: 'GET',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${token}`,
				},
			},
		);

		if (!response.ok) {
			return {
				data: null,
				error: `Session verification failed: ${response.statusText}`,
				message: 'Failed to verify session',
			};
		}

		const data = await response.json();

		// console

		return {
			data: data.data,
			error: null,
			message: 'Session verified successfully',
		};
	} catch (error) {
		return {
			data: null,
			error: error instanceof Error ? error.message : 'Network error',
			message: 'Failed to verify session',
		};
	}
};

/**
 * Check authentication status for CLI
 * Checks if token exists, validates it with backend, and returns auth status
 */
export const useAuth = async () => {
	try {
		// Step 1: Check if token exists locally
		const storedToken = getToken();

		if (!storedToken) {
			return {
				isAuthenticated: false,
				token: null,
				session: null,
				error: null,
			};
		}

		// Step 2: Verify token with backend
		const sessionResponse = await verifySession(storedToken);

		// Step 3: Check if session data exists
		if (
			sessionResponse.error ||
			!sessionResponse.data?.session?.id ||
			!sessionResponse.data?.user?.id
		) {
			// Token is invalid or expired, remove it
			removeToken();
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
