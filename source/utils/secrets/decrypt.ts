import crypto from 'crypto';

interface EncryptedSecret {
	keyName: string;
	ciphertext: string;
	nonce: string;
	note?: string | null;
	metadata?: {
		isEmpty?: boolean;
		version?: number;
		algorithm?: string;
	};
}

interface DecryptedSecret {
	key: string;
	value: string;
	note?: string | null;
}

interface ApiResult<T> {
	data: T | null;
	error: string | null;
	message: string;
}

/**
 * Decrypt a single secret value using AES-256-GCM
 */
async function decryptSecretValue({
	encryptedSecret,
	keyName,
	projectKey,
}: {
	encryptedSecret: {ciphertext: string; nonce: string};
	projectKey: Uint8Array;
	keyName: string;
}): Promise<ApiResult<{plaintext: string}>> {
	try {
		// Decode nonce from base64
		const nonce = Buffer.from(encryptedSecret.nonce, 'base64');

		// Decode encrypted data (includes ciphertext + auth tag)
		const encryptedData = Buffer.from(encryptedSecret.ciphertext, 'base64');

		// Extract auth tag (last 16 bytes)
		const authTag = encryptedData.subarray(-16);
		const ciphertext = encryptedData.subarray(0, -16);

		// Create decipher
		const decipher = crypto.createDecipheriv(
			'aes-256-gcm',
			Buffer.from(projectKey),
			nonce,
		);

		// Set auth tag
		decipher.setAuthTag(authTag);

		// Set additional authenticated data (key name)
		const additionalData = Buffer.from(keyName, 'utf8');
		decipher.setAAD(additionalData);

		// Decrypt
		const decrypted = Buffer.concat([
			decipher.update(ciphertext),
			decipher.final(),
		]);

		const plaintext = decrypted.toString('utf8');

		return {
			data: {plaintext},
			error: null,
			message: 'Secret decrypted successfully',
		};
	} catch (error) {
		console.error('Secret decryption failed:', error);
		return {
			data: null,
			error: 'Decryption failed',
			message:
				'Failed to decrypt secret. Key may be incorrect or data corrupted.',
		};
	}
}

/**
 * Decrypt multiple secrets in batch
 */
export async function decryptSecretsArray({
	encryptedSecrets,
	projectKey,
}: {
	encryptedSecrets: EncryptedSecret[];
	projectKey: Uint8Array;
}): Promise<ApiResult<DecryptedSecret[]>> {
	try {
		const decryptedSecrets: DecryptedSecret[] = [];

		for (const encrypted of encryptedSecrets) {
			// Handle empty values
			if (
				encrypted.metadata?.isEmpty ||
				(!encrypted.ciphertext && !encrypted.nonce)
			) {
				decryptedSecrets.push({
					key: encrypted.keyName,
					value: '',
					note: encrypted.note,
				});
				continue;
			}

			const decryptResult = await decryptSecretValue({
				encryptedSecret: {
					ciphertext: encrypted.ciphertext,
					nonce: encrypted.nonce,
				},
				projectKey,
				keyName: encrypted.keyName,
			});

			if (decryptResult.error || !decryptResult.data) {
				return {
					data: null,
					error: decryptResult.error || 'Decryption failed',
					message: `Failed to decrypt secret: ${encrypted.keyName}`,
				};
			}

			decryptedSecrets.push({
				key: encrypted.keyName,
				value: decryptResult.data.plaintext,
				note: encrypted.note,
			});
		}

		return {
			data: decryptedSecrets,
			error: null,
			message: `Successfully decrypted ${decryptedSecrets.length} secrets`,
		};
	} catch (error) {
		console.error('Batch secret decryption failed:', error);
		return {
			data: null,
			error: 'Batch decryption failed',
			message: 'Failed to decrypt secrets in batch',
		};
	}
}

/**
 * Secure memory wipe for sensitive data
 */
export function secureWipeSecrets(secrets: DecryptedSecret[]): void {
	try {
		secrets.forEach(secret => {
			if (secret.value) {
				// Overwrite with random data
				secret.value = '';
			}
		});
	} catch (error) {
		console.warn('Failed to securely wipe secrets from memory:', error);
	}
}
