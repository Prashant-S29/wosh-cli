import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';

const APP_NAME = 'wosh-cli';

// Security constants
const SECURITY_CONFIG = {
	scrypt: {
		memoryCost: 65536, // 64 MB (N parameter: 2^16)
		blockSize: 8, // r parameter
		parallelism: 2, // p parameter
		saltLength: 32, // 256 bits
		keyLength: 64, // 512 bits for dual-key derivation
		maxmem: 128 * 1024 * 1024, // 128 MB max memory
	},
	aes: {
		algorithm: 'aes-256-gcm' as const,
		keyLength: 32, // 256 bits
		ivLength: 16, // 128 bits
		authTagLength: 16, // 128 bits authentication tag
	},
	chacha: {
		algorithm: 'chacha20-poly1305' as const,
		keyLength: 32, // 256 bits
		ivLength: 12, // 96 bits (nonce)
		authTagLength: 16, // 128 bits authentication tag
	},
	hmac: {
		algorithm: 'sha512',
		keyLength: 64, // 512 bits
	},
};

interface EncryptedData {
	layers: number;
	timestamp: number;
	salt: string;
	iv1: string;
	iv2: string;
	authTag1: string;
	authTag2: string;
	hmac: string;
	data: string;
}

interface KeyMaterial {
	masterKey: Buffer;
	encryptionKey1: Buffer;
	encryptionKey2: Buffer;
	hmacKey: Buffer;
}

// In-memory key cache for performance (cleared on app restart)
let keyCache: KeyMaterial | null = null;

// Get config directory with proper permissions
const getConfigDir = (): string => {
	let configDir: string;

	if (process.platform === 'win32') {
		configDir = path.join(process.env['APPDATA'] || os.homedir(), APP_NAME);
	} else {
		const xdgConfig = process.env['XDG_CONFIG_HOME'];
		if (xdgConfig) {
			configDir = path.join(xdgConfig, APP_NAME);
		} else {
			configDir = path.join(os.homedir(), '.config', APP_NAME);
		}
	}

	return configDir;
};

// Ensure config directory exists with restrictive permissions
const ensureConfigDir = (): void => {
	const configDir = getConfigDir();
	if (!fs.existsSync(configDir)) {
		// 0o700 = rwx------ (only owner can access)
		fs.mkdirSync(configDir, {mode: 0o700, recursive: true});
	} else {
		// Verify and fix permissions if directory exists
		try {
			fs.chmodSync(configDir, 0o700);
		} catch (error) {
			console.warn('Could not set directory permissions:', error);
		}
	}
};

// Get salt from environment variable
const getSalt = (): Buffer => {
	const saltHex = process.env['DEVICE_STORAGE_SALT'];

	if (!saltHex) {
		throw new Error(
			'DEVICE_STORAGE_SALT environment variable is not set. ' +
				'Please set it to a 64-character hexadecimal string (32 bytes). ' +
				"Generate one with: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"",
		);
	}

	// Validate salt format
	if (!/^[0-9a-fA-F]{64}$/.test(saltHex)) {
		throw new Error(
			'DEVICE_STORAGE_SALT must be a 64-character hexadecimal string (32 bytes). ' +
				'Current value is invalid. ' +
				"Generate a new one with: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"",
		);
	}

	const salt = Buffer.from(saltHex, 'hex');

	if (salt.length !== SECURITY_CONFIG.scrypt.saltLength) {
		throw new Error(
			`DEVICE_STORAGE_SALT must be exactly ${SECURITY_CONFIG.scrypt.saltLength} bytes (64 hex characters). ` +
				`Current length: ${salt.length} bytes`,
		);
	}

	return salt;
};

// Generate stable machine ID with better persistence
const getMachineId = (): string => {
	const configDir = getConfigDir();
	ensureConfigDir(); // Ensure directory exists first

	const machineIdPath = path.join(configDir, '.machine-id');

	// ALWAYS use persistent file-based ID to avoid machine changes breaking encryption
	try {
		if (fs.existsSync(machineIdPath)) {
			const id = fs.readFileSync(machineIdPath, 'utf-8').trim();
			if (id && id.length === 64) {
				return id;
			}
			// Invalid format, regenerate
			console.warn('Invalid machine ID format, regenerating...');
		}

		// Generate new stable ID
		const newId = crypto.randomBytes(32).toString('hex');
		fs.writeFileSync(machineIdPath, newId, {mode: 0o600});
		console.log('Generated new machine ID');
		return newId;
	} catch (error) {
		// Last resort: generate ephemeral ID (not persistent across errors)
		console.error('Failed to manage machine ID file:', error);
		return crypto.randomBytes(32).toString('hex');
	}
};

// Derive master key using scrypt with machine-specific data and environment salt
const deriveMasterKey = async (): Promise<Buffer> => {
	const machineId = getMachineId();
	const password = Buffer.from(machineId + '::' + APP_NAME, 'utf-8');

	// Get salt from environment variable
	const salt = getSalt();

	// Derive key using scrypt
	return new Promise((resolve, reject) => {
		crypto.scrypt(
			password,
			salt,
			SECURITY_CONFIG.scrypt.keyLength,
			{
				N: SECURITY_CONFIG.scrypt.memoryCost,
				r: SECURITY_CONFIG.scrypt.blockSize,
				p: SECURITY_CONFIG.scrypt.parallelism,
				maxmem: SECURITY_CONFIG.scrypt.maxmem,
			},
			(err, derivedKey) => {
				if (err) reject(err);
				else resolve(derivedKey);
			},
		);
	});
};

// Derive multiple keys from master key using HKDF-like expansion
const deriveKeys = (
	masterKey: Buffer,
	salt: Buffer,
	info: string,
): {key1: Buffer; key2: Buffer; hmacKey: Buffer} => {
	const key1 = crypto.pbkdf2Sync(
		masterKey,
		Buffer.concat([salt, Buffer.from(info + ':aes', 'utf-8')]),
		100000,
		SECURITY_CONFIG.aes.keyLength,
		'sha512',
	);

	const key2 = crypto.pbkdf2Sync(
		masterKey,
		Buffer.concat([salt, Buffer.from(info + ':chacha', 'utf-8')]),
		100000,
		SECURITY_CONFIG.chacha.keyLength,
		'sha512',
	);

	const hmacKey = crypto.pbkdf2Sync(
		masterKey,
		Buffer.concat([salt, Buffer.from(info + ':hmac', 'utf-8')]),
		100000,
		SECURITY_CONFIG.hmac.keyLength,
		'sha512',
	);

	return {key1, key2, hmacKey};
};

// Get or create cached key material
const getKeyMaterial = async (salt: Buffer): Promise<KeyMaterial> => {
	// Return cached keys if available
	if (keyCache) {
		return keyCache;
	}

	// Derive new keys
	const masterKey = await deriveMasterKey();
	const {key1, key2, hmacKey} = deriveKeys(masterKey, salt, 'encrypt');

	// Cache the key material
	keyCache = {
		masterKey,
		encryptionKey1: key1,
		encryptionKey2: key2,
		hmacKey,
	};

	return keyCache;
};

// Clear key cache (useful for security-sensitive operations)
export const clearKeyCache = (): void => {
	if (keyCache) {
		// Securely zero out the key material
		keyCache.masterKey.fill(0);
		keyCache.encryptionKey1.fill(0);
		keyCache.encryptionKey2.fill(0);
		keyCache.hmacKey.fill(0);
		keyCache = null;
	}
};

// Layer 1: AES-256-GCM encryption with authentication
const encryptLayer1 = (
	data: Buffer,
	key: Buffer,
): {encrypted: Buffer; iv: Buffer; authTag: Buffer} => {
	const iv = crypto.randomBytes(SECURITY_CONFIG.aes.ivLength);
	const cipher = crypto.createCipheriv(SECURITY_CONFIG.aes.algorithm, key, iv, {
		authTagLength: SECURITY_CONFIG.aes.authTagLength,
	});

	const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
	const authTag = cipher.getAuthTag();

	return {encrypted, iv, authTag};
};

// Layer 2: ChaCha20-Poly1305 encryption with authentication
const encryptLayer2 = (
	data: Buffer,
	key: Buffer,
): {encrypted: Buffer; iv: Buffer; authTag: Buffer} => {
	const iv = crypto.randomBytes(SECURITY_CONFIG.chacha.ivLength);
	const cipher = crypto.createCipheriv(
		SECURITY_CONFIG.chacha.algorithm,
		key,
		iv,
		{
			authTagLength: SECURITY_CONFIG.chacha.authTagLength,
		},
	);

	const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
	const authTag = cipher.getAuthTag();

	return {encrypted, iv, authTag};
};

// Generate HMAC for integrity verification
const generateHMAC = (data: Buffer, key: Buffer): Buffer => {
	return crypto
		.createHmac(SECURITY_CONFIG.hmac.algorithm, key)
		.update(data)
		.digest();
};

// Verify HMAC
const verifyHMAC = (data: Buffer, hmac: Buffer, key: Buffer): boolean => {
	const computed = generateHMAC(data, key);
	return crypto.timingSafeEqual(computed, hmac);
};

// Multi-layer encryption
const encryptData = async (data: string): Promise<string> => {
	try {
		const salt = crypto.randomBytes(SECURITY_CONFIG.scrypt.saltLength);

		// Get or create key material with caching
		const keyMaterial = await getKeyMaterial(salt);

		// Convert input to buffer
		const dataBuffer = Buffer.from(data, 'utf-8');

		// Layer 1: AES-256-GCM encryption
		const layer1 = encryptLayer1(dataBuffer, keyMaterial.encryptionKey1);

		// Layer 2: ChaCha20-Poly1305 encryption
		const layer2 = encryptLayer2(layer1.encrypted, keyMaterial.encryptionKey2);

		// Generate HMAC over all encrypted data for integrity
		const hmac = generateHMAC(
			Buffer.concat([
				salt,
				layer1.iv,
				layer2.iv,
				layer1.authTag,
				layer2.authTag,
				layer2.encrypted,
			]),
			keyMaterial.hmacKey,
		);

		// Create encrypted data structure
		const encryptedData: EncryptedData = {
			layers: 2,
			timestamp: Date.now(),
			salt: salt.toString('base64'),
			iv1: layer1.iv.toString('base64'),
			iv2: layer2.iv.toString('base64'),
			authTag1: layer1.authTag.toString('base64'),
			authTag2: layer2.authTag.toString('base64'),
			hmac: hmac.toString('base64'),
			data: layer2.encrypted.toString('base64'),
		};

		// Encode as JSON with base64 encoding for safe storage
		return Buffer.from(JSON.stringify(encryptedData), 'utf-8').toString(
			'base64',
		);
	} catch (error) {
		throw new Error(
			`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
		);
	}
};

// Decrypt Layer 2: ChaCha20-Poly1305
const decryptLayer2 = (
	encrypted: Buffer,
	key: Buffer,
	iv: Buffer,
	authTag: Buffer,
): Buffer => {
	const decipher = crypto.createDecipheriv(
		SECURITY_CONFIG.chacha.algorithm,
		key,
		iv,
		{
			authTagLength: SECURITY_CONFIG.chacha.authTagLength,
		},
	);

	decipher.setAuthTag(authTag);

	return Buffer.concat([decipher.update(encrypted), decipher.final()]);
};

// Decrypt Layer 1: AES-256-GCM
const decryptLayer1 = (
	encrypted: Buffer,
	key: Buffer,
	iv: Buffer,
	authTag: Buffer,
): Buffer => {
	const decipher = crypto.createDecipheriv(
		SECURITY_CONFIG.aes.algorithm,
		key,
		iv,
		{
			authTagLength: SECURITY_CONFIG.aes.authTagLength,
		},
	);

	decipher.setAuthTag(authTag);

	return Buffer.concat([decipher.update(encrypted), decipher.final()]);
};

// Multi-layer decryption with integrity verification
const decryptData = async (encryptedData: string): Promise<string | null> => {
	try {
		// Decode base64 and parse JSON
		const jsonStr = Buffer.from(encryptedData, 'base64').toString('utf-8');
		const data: EncryptedData = JSON.parse(jsonStr);

		// Reconstruct buffers
		const salt = Buffer.from(data.salt, 'base64');
		const iv1 = Buffer.from(data.iv1, 'base64');
		const iv2 = Buffer.from(data.iv2, 'base64');
		const authTag1 = Buffer.from(data.authTag1, 'base64');
		const authTag2 = Buffer.from(data.authTag2, 'base64');
		const hmac = Buffer.from(data.hmac, 'base64');
		const encrypted = Buffer.from(data.data, 'base64');

		// Get or create key material with caching
		const keyMaterial = await getKeyMaterial(salt);

		// Verify HMAC first
		const dataToVerify = Buffer.concat([
			salt,
			iv1,
			iv2,
			authTag1,
			authTag2,
			encrypted,
		]);

		if (!verifyHMAC(dataToVerify, hmac, keyMaterial.hmacKey)) {
			throw new Error('HMAC verification failed - data may be tampered');
		}

		// Decrypt Layer 2: ChaCha20-Poly1305
		const layer2Decrypted = decryptLayer2(
			encrypted,
			keyMaterial.encryptionKey2,
			iv2,
			authTag2,
		);

		// Decrypt Layer 1: AES-256-GCM
		const layer1Decrypted = decryptLayer1(
			layer2Decrypted,
			keyMaterial.encryptionKey1,
			iv1,
			authTag1,
		);

		// Convert to string
		return layer1Decrypted.toString('utf-8');
	} catch (error) {
		console.error(
			'Decryption failed:',
			error instanceof Error ? error.message : 'Unknown error',
		);
		return null;
	}
};

/**
 * Save data securely with multi-layer encryption
 * @param filename - Name of the file to store data in
 * @param data - Data to store (will be encrypted with multiple layers)
 * @returns boolean indicating success
 */
export const saveData = async (
	filename: string,
	data: string,
): Promise<boolean> => {
	try {
		ensureConfigDir();
		const configDir = getConfigDir();
		const filePath = path.join(configDir, filename);

		const encrypted = await encryptData(data);

		// Write with restrictive permissions (0o600 = rw-------)
		fs.writeFileSync(filePath, encrypted, {mode: 0o600});

		// Verify permissions after write
		try {
			fs.chmodSync(filePath, 0o600);
		} catch (error) {
			console.warn('Could not verify file permissions:', error);
		}

		return true;
	} catch (error) {
		console.error(
			`Failed to save data to ${filename}:`,
			error instanceof Error ? error.message : 'Unknown error',
		);
		return false;
	}
};

/**
 * Retrieve and decrypt data with integrity verification
 * @param filename - Name of the file to read from
 * @returns Decrypted data or null if not found/error
 */
export const getData = async (filename: string): Promise<string | null> => {
	try {
		const configDir = getConfigDir();
		const filePath = path.join(configDir, filename);

		if (!fs.existsSync(filePath)) {
			return null;
		}

		const encrypted = fs.readFileSync(filePath, 'utf-8').trim();
		const data = await decryptData(encrypted);

		return data;
	} catch (error) {
		console.error(
			`Failed to retrieve data from ${filename}:`,
			error instanceof Error ? error.message : 'Unknown error',
		);
		return null;
	}
};

/**
 * Retrieve the raw data and return without decryption
 * @param filename - Name of the file to read from
 * @returns Raw data or null if not found/error
 */
export const getRawData = async (filename: string): Promise<string | null> => {
	try {
		const configDir = getConfigDir();
		const filePath = path.join(configDir, filename);

		if (!fs.existsSync(filePath)) {
			return null;
		}

		const rawData = fs.readFileSync(filePath, 'utf-8').trim();
		// const data = await decryptData(encrypted);

		return rawData;
	} catch (error) {
		console.error(
			`Failed to retrieve data from ${filename}:`,
			error instanceof Error ? error.message : 'Unknown error',
		);
		return null;
	}
};

/**
 * Check if data exists
 * @param filename - Name of the file to check
 * @returns boolean indicating if file exists
 */
export const hasData = (filename: string): boolean => {
	const configDir = getConfigDir();
	const filePath = path.join(configDir, filename);
	return fs.existsSync(filePath);
};

/**
 * Remove data securely (overwrite before delete)
 * @param filename - Name of the file to remove
 * @returns boolean indicating success
 */
export const removeData = (filename: string): boolean => {
	try {
		const configDir = getConfigDir();
		const filePath = path.join(configDir, filename);

		if (fs.existsSync(filePath)) {
			// Overwrite file with random data before deletion (secure delete)
			const stats = fs.statSync(filePath);
			const fileSize = stats.size;

			// Overwrite 3 times with random data
			for (let i = 0; i < 3; i++) {
				const randomData = crypto.randomBytes(fileSize);
				fs.writeFileSync(filePath, randomData);
			}

			// Finally delete
			fs.unlinkSync(filePath);
		}

		return true;
	} catch (error) {
		console.error(
			`Failed to remove data from ${filename}:`,
			error instanceof Error ? error.message : 'Unknown error',
		);
		return false;
	}
};

/**
 * Get config directory path
 */
export const getConfigPath = (): string => {
	return getConfigDir();
};

/**
 * List all encrypted files in config directory
 */
export const listEncryptedFiles = (): string[] => {
	try {
		const configDir = getConfigDir();
		if (!fs.existsSync(configDir)) {
			return [];
		}

		return fs
			.readdirSync(configDir)
			.filter(file => !file.startsWith('.')) // Exclude hidden files like .machine-id
			.filter(file => {
				const filePath = path.join(configDir, file);
				return fs.statSync(filePath).isFile();
			});
	} catch (error) {
		console.error('Failed to list encrypted files:', error);
		return [];
	}
};

/**
 * Export machine-id for backup
 * Note: Salt is now stored in DEVICE_STORAGE_SALT environment variable and should be backed up separately
 * @param backupPath - Path to save the backup
 * @returns boolean indicating success
 */
export const backupConfig = (backupPath: string): boolean => {
	try {
		const configDir = getConfigDir();
		const machineIdPath = path.join(configDir, '.machine-id');

		const backup = {
			timestamp: Date.now(),
			machineId: fs.existsSync(machineIdPath)
				? fs.readFileSync(machineIdPath, 'utf-8')
				: null,
			note: 'Salt is stored in DEVICE_STORAGE_SALT environment variable. Make sure to back it up separately!',
		};

		fs.writeFileSync(backupPath, JSON.stringify(backup, null, 2), {
			mode: 0o600,
		});

		console.log(`✅ Configuration backed up to: ${backupPath}`);
		console.log(
			`⚠️  Remember: DEVICE_STORAGE_SALT environment variable must be backed up separately!`,
		);
		return true;
	} catch (error) {
		console.error('Failed to backup configuration:', error);
		return false;
	}
};

/**
 * Restore machine-id from backup
 * Note: DEVICE_STORAGE_SALT environment variable must be set correctly before restoration
 * @param backupPath - Path to the backup file
 * @returns boolean indicating success
 */
export const restoreConfig = (backupPath: string): boolean => {
	try {
		const configDir = getConfigDir();
		ensureConfigDir();

		const backup = JSON.parse(fs.readFileSync(backupPath, 'utf-8'));

		if (backup.machineId) {
			const machineIdPath = path.join(configDir, '.machine-id');
			fs.writeFileSync(machineIdPath, backup.machineId, {mode: 0o600});
		}

		// Clear cache to force re-derivation with restored config
		clearKeyCache();

		console.log(`✅ Configuration restored from: ${backupPath}`);
		console.log(
			`⚠️  Make sure DEVICE_STORAGE_SALT environment variable is set correctly!`,
		);
		return true;
	} catch (error) {
		console.error('Failed to restore configuration:', error);
		return false;
	}
};

/**
 * Validate that DEVICE_STORAGE_SALT is properly configured
 * @returns boolean indicating if salt is valid
 */
export const validateSaltConfig = (): boolean => {
	try {
		getSalt(); // Will throw if invalid
		console.log('✅ DEVICE_STORAGE_SALT is properly configured');
		return true;
	} catch (error) {
		console.error('❌ DEVICE_STORAGE_SALT validation failed:');
		console.error(error instanceof Error ? error.message : 'Unknown error');
		return false;
	}
};

/**
 * Generate a new salt value for DEVICE_STORAGE_SALT
 * This is a helper function - the actual salt should be set as an environment variable
 * @returns 64-character hexadecimal string (32 bytes)
 */
export const generateSalt = (): string => {
	return crypto.randomBytes(SECURITY_CONFIG.scrypt.saltLength).toString('hex');
};
