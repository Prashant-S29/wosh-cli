import {
	saveData,
	getData,
	hasData,
	removeData,
	getRawData,
} from '../utils.deviceStorage.js';
import crypto from 'crypto';
import {decryptKeys} from './utils.decryptionKeys.js';

const CLI_TOKEN_FILENAME = 'cli-token';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const SALT_LENGTH = 32;
const AUTH_TAG_LENGTH = 16;

/**
 * Validate CLI token format
 * @param token - CLI token to validate
 * @returns boolean indicating if token format is valid
 */
export const isValidCLITokenFormat = (token: string): boolean => {
	try {
		// Should be base64url encoded
		const decoded = Buffer.from(token, 'base64url');
		// Minimum length check (encrypted data + auth tag)
		return decoded.length > 32;
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
 * @returns CLI encrypted token blob or null if not found
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

interface CLITokenData {
	hashKeys: string;
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

export async function decryptCLIToken(
	token: string,
): Promise<DecryptCLITokenResult> {
	try {
		const cliTokenHash = process.env['CLI_TOKEN_HASH'];

		if (!cliTokenHash) {
			return {
				data: null,
				error: 'Server configuration error',
				message: 'CLI_TOKEN_HASH environment variable is not set',
			};
		}

		// Decode the token
		const combined = Buffer.from(token, 'base64url');

		// Extract components
		const salt = combined.subarray(0, SALT_LENGTH);
		const iv = combined.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
		const authTag = combined.subarray(combined.length - AUTH_TAG_LENGTH);
		const encrypted = combined.subarray(
			SALT_LENGTH + IV_LENGTH,
			combined.length - AUTH_TAG_LENGTH,
		);

		// Derive the same key
		const key = crypto.scryptSync(cliTokenHash, salt, 32, {
			N: 16384,
			r: 8,
			p: 1,
			maxmem: 64 * 1024 * 1024,
		});

		const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
		decipher.setAuthTag(authTag);

		// Decrypt
		const decrypted = Buffer.concat([
			decipher.update(encrypted),
			decipher.final(),
		]);

		const tokenData = JSON.parse(decrypted.toString('utf8')) as CLITokenData;

		// decrypt keys
		const keys = decryptKeys(tokenData.hashKeys);

		if (keys.error || !keys.data) {
			return {
				data: null,
				error: keys.error,
				message: keys.message,
			};
		}

		return {
			data: {
				masterPassphrase: keys.data.masterPassphrase,
				pin: keys.data.pin,
				orgId: tokenData.orgId,
				projectId: tokenData.projectId,
			},
			error: null,
			message: 'Success',
		};
	} catch (error) {
		console.error('Failed to decrypt CLI token:', error);
		return {
			data: null,
			error: 'Invalid or expired token',
			message: 'Failed to decrypt CLI token',
		};
	}
}
