import { BACKEND_BASE_URL } from '../../constants/index.js';
import {GetSessionResponse} from '../../types/auth/index.js';
import {SafeApiResponse} from '../../types/index.js';
import {
	saveData,
	getData,
	hasData,
	removeData,
} from '../utils.deviceStorage.js';

const SESSION_TOKEN_FILENAME = 'session-token';

/**
 * Save session token securely
 * @param token - Session token to store
 * @returns boolean indicating success
 */
export const saveSessionToken = async (token: string): Promise<boolean> => {
	return await saveData(SESSION_TOKEN_FILENAME, token);
};

/**
 * Retrieve session token
 * @returns Session token or null if not found
 */
export const getSessionToken = async (): Promise<string | null> => {
	return await getData(SESSION_TOKEN_FILENAME);
};

/**
 * Check if session token exists
 * @returns boolean indicating if token exists
 */
export const hasSessionToken = (): boolean => {
	return hasData(SESSION_TOKEN_FILENAME);
};

/**
 * Remove session token (logout)
 * @returns boolean indicating success
 */
export const removeSessionToken = (): boolean => {
	return removeData(SESSION_TOKEN_FILENAME);
};

export const getSessionTokenData = async () => {
	try {
		const sessionToken = await getSessionToken();

		if (!sessionToken) {
			return {
				data: null,
				error: null,
				message: 'Session token not found',
			};
		}

		const sessionResponse = await fetch(
			`${BACKEND_BASE_URL}/api/auth/session`,
			{
				method: 'GET',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${sessionToken}`,
				},
			},
		);

		if (!sessionResponse.ok) {
			removeSessionToken();
			return {
				data: null,
				error: `Session verification failed: ${sessionResponse.statusText}`,
				message: 'Failed to verify session',
			};
		}

		const sessionResult =
			(await sessionResponse.json()) as SafeApiResponse<GetSessionResponse>;

		if (!sessionResult.data?.session?.id || !sessionResult.data?.user?.id) {
			removeSessionToken();
			return {
				data: null,
				error: 'Invalid session. Please log in again.',
				message: 'Failed to verify session',
			};
		}

		return {
			data: sessionResult.data,
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
