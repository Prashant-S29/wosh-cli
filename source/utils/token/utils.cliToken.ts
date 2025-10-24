import {
	saveData,
	getData,
	hasData,
	removeData,
	getRawData,
} from '../utils.deviceStorage.js';
import crypto from 'crypto';

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
	masterPassphrase: string;
	pin?: string;
	orgInfo: {id: string; name: string};
	projectInfo: {id: string; name: string};
}

interface DecryptCLITokenResult {
	data: CLITokenData | null;
	error: string | null;
	message: string;
}

export async function decryptCLIToken({
	token,
}: {
	token: string;
}): Promise<DecryptCLITokenResult> {
	try {
		const cliTokenHash = process.env['CLI_TOKEN_HASH'];

		if (!cliTokenHash) {
			console.error('CRITICAL: CLI_TOKEN_HASH environment variable is not set');
			return {
				data: null,
				error: 'Server configuration error',
				message: 'Failed to decrypt CLI token',
			};
		}

		// Decode the token from URL-safe base64
		const combined = Buffer.from(token, 'base64url');

		// Verify minimum length
		const minLength = SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH + 1;
		if (combined.length < minLength) {
			return {
				data: null,
				error: 'Invalid token format',
				message: 'Token is too short or corrupted',
			};
		}

		// Extract components: salt + iv + encrypted + authTag
		let offset = 0;
		const salt = combined.subarray(offset, offset + SALT_LENGTH);
		offset += SALT_LENGTH;

		const iv = combined.subarray(offset, offset + IV_LENGTH);
		offset += IV_LENGTH;

		const authTag = combined.subarray(combined.length - AUTH_TAG_LENGTH);
		const encrypted = combined.subarray(
			offset,
			combined.length - AUTH_TAG_LENGTH,
		);

		// Derive the same key using CLI_TOKEN_HASH and extracted salt
		const key = crypto.scryptSync(cliTokenHash, salt, 32);

		const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
		decipher.setAuthTag(authTag);

		// Decrypt
		const decrypted = Buffer.concat([
			decipher.update(encrypted),
			decipher.final(),
		]);

		// Parse JSON
		const tokenData: CLITokenData = JSON.parse(decrypted.toString('utf8'));

		return {
			data: tokenData,
			error: null,
			message: 'CLI token decrypted successfully',
		};
	} catch (error) {
		console.error('Failed to decrypt CLI token:', error);
		return {
			data: null,
			error:
				error instanceof Error ? error.message : 'Failed to decrypt CLI token',
			message: 'Invalid or corrupted CLI token',
		};
	}
}
