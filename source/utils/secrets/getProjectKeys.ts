import crypto from 'crypto';
import {x25519} from '@noble/curves/ed25519.js';
import {hkdf} from '@noble/hashes/hkdf.js';
import {sha256} from '@noble/hashes/sha2.js';

import {getAuth} from '../auth/getAuth.js';

interface ProjectKeyCredentials {
	masterPassphrase: string;
	pin?: string;
}

interface OrgKeysData {
	combinationSalt: string;
	iv: string;
	publicKey: string;
	privateKeyEncrypted: string;
	salt: string;
	pinSalt?: string;
	mkdfConfig: {
		enabledFactors: string[];
		requiredFactors: number;
	};
	deviceFingerprint: string;
	deviceKeyEncrypted: string;
	deviceKeyIv: string;
	deviceKeySalt: string;
	mkdfVersion: string;
}

interface WrappedProjectKey {
	ciphertext: string;
	iv: string;
	ephemeralPublicKey: string;
	algorithm: string;
	version: number;
}

interface ApiResult<T> {
	data: T | null;
	error: string | null;
	message: string;
}

/**
 * Generate device fingerprint
 */
// async function generateDeviceFingerprint(): Promise<{fingerprint: string}> {
// 	const components = [
// 		process.platform,
// 		process.arch,
// 		process.version,
// 		require('os').hostname(),
// 		require('os').userInfo().username,
// 	];

// 	const combined = components.join('|');
// 	const hash = crypto.createHash('sha256').update(combined).digest('hex');

// 	return {fingerprint: hash};
// }

/**
 * Derive key using PBKDF2
 */
// async function deriveKey(
// 	password: string,
// 	salt: Uint8Array,
// 	iterations: number,
// 	keyLength: number,
// ): Promise<Uint8Array> {
// 	return new Promise((resolve, reject) => {
// 		crypto.pbkdf2(
// 			password,
// 			Buffer.from(salt),
// 			iterations,
// 			keyLength,
// 			'sha256',
// 			(err, derivedKey) => {
// 				if (err) reject(err);
// 				else resolve(new Uint8Array(derivedKey));
// 			},
// 		);
// 	});
// }

/**
 * Combine multiple keys using XOR
 */
function combineKeys(keys: Uint8Array[]): Uint8Array {
	if (keys.length === 0) {
		throw new Error('No keys to combine');
	}

	const firstKey = keys[0];
	if (!firstKey) {
		throw new Error('Invalid key array');
	}

	const keyLength = firstKey.length;
	const combined = new Uint8Array(keyLength);

	for (let i = 0; i < keyLength; i++) {
		let value = 0;
		for (const key of keys) {
			// Optional: Add a safety check
			// if (key.length !== keyLength) {
			// 	throw new Error('All keys must have the same length');
			// }

			value ^= key[i]!;
		}
		combined[i] = value;
	}

	return combined;
}

/**
 * Decrypt organization private key using MKDF
 */
async function retrieveOrgPrivateKeyMKDF(
	masterPassphrase: string,
	deviceFingerprint: string,
	pin: string | undefined,
	orgKeys: OrgKeysData,
): Promise<ApiResult<Uint8Array>> {
	try {
		const derivedKeys: Uint8Array[] = [];

		// Derive master passphrase key (using PBKDF2, not HKDF)
		const passphraseKey = await deriveKeyPBKDF2(
			masterPassphrase,
			Buffer.from(orgKeys.salt, 'base64'),
			100000,
			32,
		);
		derivedKeys.push(passphraseKey);

		// Derive device key (using HKDF with proper info string)
		const deviceKey = deriveKeyHKDF(
			deviceFingerprint,
			Buffer.from(orgKeys.deviceKeySalt, 'base64'),
			'wosh-device-factor-v1',
			32,
		);
		derivedKeys.push(deviceKey);

		// Derive PIN key if required (using PBKDF2, not HKDF)
		if (
			orgKeys.mkdfConfig.enabledFactors.includes('pin') &&
			pin &&
			orgKeys.pinSalt
		) {
			const pinKey = await deriveKeyPBKDF2(
				pin,
				Buffer.from(orgKeys.pinSalt, 'base64'),
				50000, // Lower iterations for PIN
				32,
			);
			derivedKeys.push(pinKey);
		}

		// Combine all keys using XOR
		const combinedEntropy = combineKeys(derivedKeys);

		// Use HKDF to derive final master key (matching web app)
		const masterKey = deriveKeyHKDF(
			combinedEntropy,
			Buffer.from(orgKeys.combinationSalt, 'base64'),
			'wosh-mkdf-master-v1',
			32,
		);

		// Derive storage key from master key
		const storageKey = deriveKeyHKDF(
			masterKey,
			undefined,
			'local-storage-v1',
			32,
		);

		// Decrypt private key using Web Crypto compatible format
		const encryptedData = Buffer.from(orgKeys.privateKeyEncrypted, 'base64');
		const iv = Buffer.from(orgKeys.iv, 'base64');

		// Extract auth tag (last 16 bytes) and ciphertext
		const authTag = encryptedData.subarray(-16);
		const ciphertext = encryptedData.subarray(0, -16);

		// Create decipher
		const decipher = crypto.createDecipheriv('aes-256-gcm', storageKey, iv);
		decipher.setAuthTag(authTag);

		// Decrypt
		const decrypted = Buffer.concat([
			decipher.update(ciphertext),
			decipher.final(),
		]);

		// Secure cleanup
		crypto.randomFillSync(combinedEntropy);
		crypto.randomFillSync(masterKey);
		crypto.randomFillSync(storageKey);

		return {
			data: new Uint8Array(decrypted),
			error: null,
			message: 'Private key decrypted successfully',
		};
	} catch (error) {
		console.error('Failed to decrypt private key:', error);
		return {
			data: null,
			error: 'Decryption failed',
			message:
				'Failed to decrypt organization private key. Check your credentials.',
		};
	}
}

/**
 * Derive key using PBKDF2 (matching web app for passphrase and PIN)
 */
async function deriveKeyPBKDF2(
	password: string,
	salt: Buffer,
	iterations: number,
	keyLength: number,
): Promise<Uint8Array> {
	return new Promise((resolve, reject) => {
		crypto.pbkdf2(
			password,
			salt,
			iterations,
			keyLength,
			'sha256',
			(err, derivedKey) => {
				if (err) reject(err);
				else resolve(new Uint8Array(derivedKey));
			},
		);
	});
}

/**
 * Derive key using HKDF (matching web app for device and combination)
 */
function deriveKeyHKDF(
	input: string | Uint8Array,
	salt: Buffer | undefined,
	info: string,
	keyLength: number,
): Uint8Array {
	const inputBuffer =
		typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input);

	const infoBuffer = Buffer.from(info, 'utf8');

	// Node.js HKDF
	const key = crypto.hkdfSync(
		'sha256',
		inputBuffer,
		salt || Buffer.alloc(0),
		infoBuffer,
		keyLength,
	);

	return new Uint8Array(key);
}

/**
 * Derive project storage key
 */
async function deriveProjectStorageKey(
	orgPrivateKey: Uint8Array,
	projectId: string,
): Promise<ApiResult<Uint8Array>> {
	try {
		const hash = crypto
			.createHash('sha256')
			.update(Buffer.from(orgPrivateKey))
			.update(projectId)
			.digest();

		return {
			data: new Uint8Array(hash),
			error: null,
			message: 'Storage key derived successfully',
		};
	} catch (error) {
		return {
			data: null,
			error: 'Key derivation failed',
			message: 'Failed to derive project storage key',
		};
	}
}

/**
 * Unwrap project key using organization private key
 */
async function unwrapProjectKey(
	wrappedKey: WrappedProjectKey,
	orgPrivateKey: Uint8Array,
): Promise<ApiResult<Uint8Array>> {
	try {
		// Validate inputs
		if (!wrappedKey) {
			return {
				data: null,
				error: 'Missing wrapped key',
				message: 'No wrapped key provided for unwrapping',
			};
		}

		if (
			wrappedKey.algorithm !== 'aes-256-gcm-x25519' ||
			wrappedKey.version !== 1
		) {
			return {
				data: null,
				error: 'Unsupported format',
				message: 'Unsupported key wrapping format or version',
			};
		}

		if (!orgPrivateKey || orgPrivateKey.length !== 32) {
			return {
				data: null,
				error: 'Invalid organization private key',
				message: 'Organization private key must be 32 bytes',
			};
		}

		if (
			!wrappedKey.ciphertext ||
			!wrappedKey.iv ||
			!wrappedKey.ephemeralPublicKey
		) {
			return {
				data: null,
				error: 'Incomplete wrapped key',
				message: 'Wrapped key is missing required components',
			};
		}

		// Decode base64 components
		const ciphertextBuffer = Buffer.from(wrappedKey.ciphertext, 'base64');
		const ivBuffer = Buffer.from(wrappedKey.iv, 'base64');
		const ephemeralPublicKeyBuffer = Buffer.from(
			wrappedKey.ephemeralPublicKey,
			'base64',
		);

		// Convert Ed25519 org private key to X25519 for ECDH
		// Just use the first 32 bytes directly (Ed25519 key can be used as X25519)
		const orgX25519PrivateKey = orgPrivateKey.slice(0, 32);

		// Perform X25519 key agreement to recreate shared secret
		let sharedSecret: Uint8Array;
		try {
			sharedSecret = x25519.getSharedSecret(
				orgX25519PrivateKey,
				new Uint8Array(ephemeralPublicKeyBuffer),
			);
		} catch (error) {
			console.error('X25519 key agreement failed:', error);
			return {
				data: null,
				error: 'Failed to recreate shared secret during unwrapping',
				message: 'Failed to recreate shared secret during unwrapping',
			};
		}

		// Derive the same encryption key using HKDF
		let wrappingKey: Uint8Array;
		try {
			const info = new TextEncoder().encode('project-key-wrapping-v1');
			wrappingKey = hkdf(sha256, sharedSecret, undefined, info, 32);
		} catch (error) {
			console.error('HKDF derivation failed:', error);
			secureWipe(sharedSecret);
			return {
				data: null,
				error: 'Failed to derive unwrapping key',
				message: 'Failed to derive unwrapping key',
			};
		}

		// Extract auth tag (last 16 bytes) from ciphertext
		const authTag = ciphertextBuffer.subarray(-16);
		const actualCiphertext = ciphertextBuffer.subarray(0, -16);

		// Decrypt project key using AES-256-GCM
		const decipher = crypto.createDecipheriv(
			'aes-256-gcm',
			Buffer.from(wrappingKey),
			ivBuffer,
		);

		decipher.setAuthTag(authTag);

		let decrypted: Buffer;
		try {
			decrypted = Buffer.concat([
				decipher.update(actualCiphertext),
				decipher.final(),
			]);
		} catch (error) {
			console.error('Decryption failed:', error);
			secureWipe(sharedSecret);
			secureWipe(wrappingKey);
			return {
				data: null,
				error: 'Decryption failed',
				message: 'Invalid organization key or corrupted wrapped project key',
			};
		}

		// Clean up sensitive data
		secureWipe(sharedSecret);
		secureWipe(wrappingKey);

		return {
			data: new Uint8Array(decrypted),
			error: null,
			message: 'Project key unwrapped successfully',
		};
	} catch (error) {
		console.error('Failed to unwrap project key:', error);
		return {
			data: null,
			error: 'Unwrap failed',
			message: 'Failed to unwrap project key',
		};
	}
}

/**
 * Fetch organization keys from server
 */
async function fetchOrgKeysFromServer(
	organizationId: string,
): Promise<ApiResult<OrgKeysData>> {
	try {
		const {token} = await getAuth();

		if (!token) {
			console.log('No token found');

			return {
				data: null,
				error: 'No token found',
				message: 'Failed to fetch organization keys from server',
			};
		}

		const response = await fetch(
			`${process.env['BACKEND_BASE_URL']}/api/organization/keys?orgId=${organizationId}`,
			{
				headers: {
					Authorization: `Bearer ${token}`,
					'Content-Type': 'application/json',
				},
			},
		);

		const result = await response.json();

		if (result.error || !result.data?.factorConfig) {
			console.log('Failed to load keys', result);

			return {
				data: null,
				error: 'Failed to load keys',
				message: 'Failed to load security configuration from server',
			};
		}

		return {
			data: {
				combinationSalt: result.data.deviceInfo.combinationSalt,
				iv: result.data.encryptionIv,
				publicKey: result.data.publicKey,
				privateKeyEncrypted: result.data.privateKeyEncrypted,
				salt: result.data.keyDerivationSalt,
				...(result.data.deviceInfo.pinSalt
					? {pinSalt: result.data.deviceInfo.pinSalt}
					: {}),
				mkdfConfig: {
					enabledFactors: result.data.factorConfig.enabledFactors,
					requiredFactors: result.data.factorConfig.requiredFactors,
				},
				deviceFingerprint: result.data.deviceInfo.deviceFingerprint,
				deviceKeyEncrypted: result.data.deviceInfo.encryptedDeviceKey,
				deviceKeyIv: result.data.deviceInfo.keyDerivationSalt,
				deviceKeySalt: result.data.deviceInfo.keyDerivationSalt,
				mkdfVersion: result.data.mkdfVersion,
			},
			error: null,
			message: 'Keys fetched successfully',
		};
	} catch (error) {
		console.log('Error fetching keys', error);

		return {
			data: null,
			error: 'Network error',
			message: 'Failed to fetch organization keys from server',
		};
	}
}

/**
 * Fetch project keys from server
 */
async function fetchProjectKeysFromServer(
	organizationId: string,
	projectId: string,
): Promise<ApiResult<WrappedProjectKey>> {
	try {
		const {token} = await getAuth();

		if (!token) {
			return {
				data: null,
				error: 'No token found',
				message: 'Failed to fetch project keys from server',
			};
		}

		const response = await fetch(
			`${process.env['BACKEND_BASE_URL']}/api/project/keys?orgId=${organizationId}&projectId=${projectId}`,
			{
				headers: {
					Authorization: `Bearer ${token}`,
					'Content-Type': 'application/json',
				},
			},
		);

		const result = await response.json();

		if (result.error || !result.data?.wrappedSymmetricKey) {
			return {
				data: null,
				error: 'Failed to load project key',
				message: 'Failed to load project key from server',
			};
		}

		const wrappedKey = JSON.parse(
			result.data.wrappedSymmetricKey,
		) as WrappedProjectKey;

		return {
			data: wrappedKey,
			error: null,
			message: 'Project key fetched successfully',
		};
	} catch (error) {
		return {
			data: null,
			error: 'Network error',
			message: 'Failed to fetch project key from server',
		};
	}
}

/**
 * Secure wipe of sensitive data (add this if not present)
 */
function secureWipe(data: Uint8Array): void {
	if (data) {
		crypto.randomFillSync(data);
	}
}

/**
 * Main function to recover project key
 */
export async function recoverProjectKey(
	credentials: ProjectKeyCredentials,
	organizationId: string,
	projectId: string,
): Promise<ApiResult<Uint8Array>> {
	let orgPrivateKey: Uint8Array | null = null;
	let storageKey: Uint8Array | null = null;

	try {
		// Generate device fingerprint
		// const fingerprintResult = await generateDeviceFingerprint();
		// if (!fingerprintResult.fingerprint) {
		// 	return {
		// 		data: null,
		// 		error: 'Device fingerprint generation failed',
		// 		message: 'Failed to generate device fingerprint',
		// 	};
		// }

		// Fetch organization keys from server
		const orgKeysResult = await fetchOrgKeysFromServer(organizationId);
		if (orgKeysResult.error || !orgKeysResult.data) {
			return {
				data: null,
				error: orgKeysResult.error,
				message: orgKeysResult.message,
			};
		}

		// Verify device fingerprint
		// if (
		// 	orgKeysResult.data.deviceFingerprint !== fingerprintResult.fingerprint
		// ) {
		// 	console.log('Device verification failed');
		// 	// return {
		// 	// 	data: null,
		// 	// 	error: 'Device verification failed',
		// 	// 	message: 'This device is not registered for this organization',
		// 	// };
		// }

		// Recover organization private key using MKDF
		const privateKeyResult = await retrieveOrgPrivateKeyMKDF(
			credentials.masterPassphrase,
			// fingerprintResult.fingerprint,
			orgKeysResult.data.deviceFingerprint,
			credentials.pin,
			orgKeysResult.data,
		);

		if (privateKeyResult.error || !privateKeyResult.data) {
			return {
				data: null,
				error: privateKeyResult.error,
				message: privateKeyResult.message,
			};
		}

		orgPrivateKey = privateKeyResult.data;

		// Derive storage key for this project
		const storageKeyResult = await deriveProjectStorageKey(
			orgPrivateKey,
			projectId,
		);
		if (storageKeyResult.error || !storageKeyResult.data) {
			return {
				data: null,
				error: storageKeyResult.error,
				message: storageKeyResult.message,
			};
		}

		storageKey = storageKeyResult.data;

		// Fetch wrapped project key from server
		const wrappedKeyResult = await fetchProjectKeysFromServer(
			organizationId,
			projectId,
		);

		if (wrappedKeyResult.error || !wrappedKeyResult.data) {
			return {
				data: null,
				error: wrappedKeyResult.error,
				message: wrappedKeyResult.message,
			};
		}

		// Unwrap project key using organization private key
		const unwrapResult = await unwrapProjectKey(
			wrappedKeyResult.data,
			orgPrivateKey,
		);

		if (unwrapResult.error || !unwrapResult.data) {
			return {
				data: null,
				error: unwrapResult.error,
				message: unwrapResult.message,
			};
		}

		return {
			data: unwrapResult.data,
			error: null,
			message: 'Project key recovered successfully',
		};
	} catch (error) {
		console.error('Project key recovery failed:', error);
		return {
			data: null,
			error: 'Failed to recover project key',
			message: 'Failed to recover project key',
		};
	} finally {
		// Secure cleanup
		if (orgPrivateKey) {
			secureWipe(orgPrivateKey);
		}
		if (storageKey) {
			secureWipe(storageKey);
		}
	}
}
