import crypto from 'crypto';

interface KeyData {
	masterPassphrase: string;
	pin?: string;
}

interface EncryptedData {
	encryptedData: string;
	iv: string;
	authTag: string;
	salt: string;
}

export function decryptKeys(hashKeys: string) {
	const SALT = process.env['KEYS_ENCRYPTION_SALT'];

	if (!SALT || SALT.length < 32) {
		return {
			data: null,
			error: 'KEYS_ENCRYPTION_SALT must be set and at least 32 characters',
			message: 'Failed to decrypt keys',
		};
	}

	try {
		const packagedData = JSON.parse(
			Buffer.from(hashKeys, 'base64').toString('utf8'),
		) as EncryptedData;

		const encryptedData = packagedData.encryptedData;
		const iv = Buffer.from(packagedData.iv, 'base64');
		const authTag = Buffer.from(packagedData.authTag, 'base64');
		const keySalt = Buffer.from(packagedData.salt, 'base64');

		const derivedKey = crypto.pbkdf2Sync(SALT, keySalt, 600000, 32, 'sha512');

		const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
		decipher.setAuthTag(authTag);

		let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
		decrypted += decipher.final('utf8');

		const keys = JSON.parse(decrypted) as KeyData;

		return {
			data: keys,
			error: null,
			message: 'Keys decrypted successfully',
		};
	} catch (error) {
		console.error('Failed to decrypt keys:', error);
		return {
			data: null,
			error: error instanceof Error ? error.message : 'Failed to decrypt keys',
			message: 'Failed to decrypt keys',
		};
	}
}
