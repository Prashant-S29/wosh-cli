import {
	saveData,
	getData,
	hasData,
	removeData,
	getRawData,
} from '../utils.deviceStorage.js';

interface CLITokenData {
	masterPassphrase: string;
	pin?: string;
	orgId: string;
	projectId: string;
}

interface DecryptCLITokenResult {
	data: {
		masterPassphrase: string;
		pin?: string;
		orgId: string;
		projectId: string;
	} | null;
	error: string | null;
	message: string;
}

const CLI_TOKEN_FILENAME = 'cli-token';

/**
 * Validate CLI token format
 * @param token - CLI token to validate
 * @returns boolean indicating if token format is valid
 */
export const isValidCLITokenFormat = (token: string): boolean => {
	try {
		// Should be base64url encoded
		const decoded = Buffer.from(token, 'base64url').toString('utf8');
		// Try to parse as JSON
		const parsed: CLITokenData = JSON.parse(decoded);
		// Check for required fields
		return !!(parsed.masterPassphrase && parsed.orgId && parsed.projectId);
	} catch {
		return false;
	}
};

/**
 * Save CLI token securely
 * @param token - CLI token to store
 * @returns boolean indicating success
 */
export const saveCLIToken = async (token: string): Promise<boolean> => {
	// Validate token format before saving
	if (!isValidCLITokenFormat(token)) {
		console.error('Invalid CLI token format');
		return false;
	}
	return await saveData(CLI_TOKEN_FILENAME, token);
};

/**
 * Retrieve CLI token
 * @returns CLI token or null if not found
 */
export const getCLIToken = async (): Promise<string | null> => {
	return await getData(CLI_TOKEN_FILENAME);
};

/**
 * Retrieve Encrypted CLI token blob
 * @returns CLI token blob or null if not found
 */
export const getEncryptedCLITokenBlob = async (): Promise<string | null> => {
	return await getRawData(CLI_TOKEN_FILENAME);
};

/**
 * Check if CLI token exists
 * @returns boolean indicating if token exists
 */
export const hasCLIToken = (): boolean => {
	return hasData(CLI_TOKEN_FILENAME);
};

/**
 * Remove CLI token
 * @returns boolean indicating success
 */
export const removeCLIToken = (): boolean => {
	return removeData(CLI_TOKEN_FILENAME);
};

export async function decryptCLIToken(
	token: string,
): Promise<DecryptCLITokenResult> {
	try {
		// Decode the base64url token
		const decoded = Buffer.from(token, 'base64url').toString('utf8');
		const tokenData = JSON.parse(decoded) as CLITokenData;

		// Validate required fields
		if (
			!tokenData.masterPassphrase ||
			!tokenData.orgId ||
			!tokenData.projectId
		) {
			return {
				data: null,
				error: 'Invalid token structure',
				message: 'CLI token is missing required fields',
			};
		}

		return {
			data: tokenData,
			error: null,
			message: 'Success',
		};
	} catch (error) {
		console.error('Failed to decode CLI token:', error);
		return {
			data: null,
			error: 'Invalid token format',
			message: 'Failed to decode CLI token',
		};
	}
}
