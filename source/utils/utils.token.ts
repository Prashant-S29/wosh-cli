import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';

const APP_NAME = 'wosh-cli';

// Get config directory
const getConfigDir = (): string => {
	let configDir: string;

	if (process.platform === 'win32') {
		configDir = path.join(process.env['APPDATA'] || os.homedir(), APP_NAME);
	} else {
		// Linux, macOS, and other Unix-like systems
		const xdgConfig = process.env['XDG_CONFIG_HOME'];
		if (xdgConfig) {
			configDir = path.join(xdgConfig, APP_NAME);
		} else {
			configDir = path.join(os.homedir(), '.config', APP_NAME);
		}
	}

	return configDir;
};

// Ensure config directory exists with proper permissions
const ensureConfigDir = (): void => {
	const configDir = getConfigDir();
	if (!fs.existsSync(configDir)) {
		// 0o700 = rwx------ (only owner can access)
		fs.mkdirSync(configDir, {mode: 0o700, recursive: true});
	}
};

// Generate or retrieve machine-specific encryption key
const getEncryptionKey = (): Buffer => {
	const configDir = getConfigDir();
	const keyPath = path.join(configDir, '.key');

	if (fs.existsSync(keyPath)) {
		const keyHex = fs.readFileSync(keyPath, 'utf-8').trim();
		const keyBuffer = Buffer.from(keyHex, 'hex');

		// Validate key length
		if (keyBuffer.length !== 32) {
			console.warn('Invalid key length in file, regenerating...');
			fs.unlinkSync(keyPath);
			return generateAndSaveKey();
		}

		return keyBuffer;
	}

	return generateAndSaveKey();
};

// Generate and save encryption key
const generateAndSaveKey = (): Buffer => {
	const machineId = getMachineId();
	const hash = crypto
		.createHash('sha256')
		.update(machineId + APP_NAME)
		.digest();

	// Ensure we have exactly 32 bytes for AES-256
	if (hash.length !== 32) {
		throw new Error(
			`Key generation failed: expected 32 bytes, got ${hash.length}`,
		);
	}

	const keyHex = hash.toString('hex');
	const configDir = getConfigDir();
	const keyPath = path.join(configDir, '.key');

	// Save key with restricted permissions
	fs.writeFileSync(keyPath, keyHex, {mode: 0o600});

	return hash;
};

// Generate unique machine identifier
const getMachineId = (): string => {
	try {
		const hostname = os.hostname();
		const platform = os.platform();
		const arch = os.arch();
		const userInfo = os.userInfo();
		return `${hostname}-${platform}-${arch}-${userInfo.uid || userInfo.username}`;
	} catch {
		return `${Date.now()}-${Math.random()}`;
	}
};

// Encrypt token before storing
const encryptToken = (token: string): string => {
	const key = getEncryptionKey();

	// Validate key before using
	if (!key || key.length !== 32) {
		throw new Error(
			`Invalid key length: expected 32 bytes, got ${key?.length || 0}`,
		);
	}

	const iv = crypto.randomBytes(16);
	const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

	let encrypted = cipher.update(token, 'utf-8', 'hex');
	encrypted += cipher.final('hex');

	// Return IV + encrypted token (IV needed for decryption)
	return `${iv.toString('hex')}:${encrypted}`;
};

// Decrypt stored token
const decryptToken = (encryptedData: string): string | null => {
	try {
		const key = getEncryptionKey();

		if (!key || key.length !== 32) {
			throw new Error(
				`Invalid key length: expected 32 bytes, got ${key?.length || 0}`,
			);
		}

		const parts = encryptedData.split(':');

		if (parts.length !== 2 || !parts[0] || !parts[1]) {
			throw new Error('Invalid encrypted token format');
		}

		const [ivHex, encrypted] = parts;
		const iv = Buffer.from(ivHex, 'hex');
		const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

		const decrypted =
			decipher.update(encrypted, 'hex', 'utf-8') + decipher.final('utf-8');

		return decrypted;
	} catch (error) {
		console.error(
			'Failed to decrypt token:',
			error instanceof Error ? error.message : 'Unknown error',
		);
		return null;
	}
};

// Save token securely
export const saveToken = (token: string): boolean => {
	try {
		ensureConfigDir();
		const configDir = getConfigDir();
		const tokenPath = path.join(configDir, 'token');

		// Save token as-is (don't decode)
		const encrypted = encryptToken(token);
		// 0o600 = rw------- (only owner can read/write)
		fs.writeFileSync(tokenPath, encrypted, {mode: 0o600});

		return true;
	} catch (error) {
		console.error(
			'Failed to save token:',
			error instanceof Error ? error.message : 'Unknown error',
		);
		return false;
	}
};

// Retrieve and decrypt token
export const getToken = (): string | null => {
	try {
		const configDir = getConfigDir();
		const tokenPath = path.join(configDir, 'token');

		if (!fs.existsSync(tokenPath)) {
			return null;
		}

		const encrypted = fs.readFileSync(tokenPath, 'utf-8').trim();
		const token = decryptToken(encrypted);

		return token;
	} catch (error) {
		console.error(
			'Failed to retrieve token:',
			error instanceof Error ? error.message : 'Unknown error',
		);
		return null;
	}
};

// Helper: Check if token exists
export const hasToken = (): boolean => {
	const configDir = getConfigDir();
	const tokenPath = path.join(configDir, 'token');
	return fs.existsSync(tokenPath);
};

// Helper: Remove token (logout)
export const removeToken = (): boolean => {
	try {
		const configDir = getConfigDir();
		const tokenPath = path.join(configDir, 'token');

		if (fs.existsSync(tokenPath)) {
			fs.unlinkSync(tokenPath);
		}

		return true;
	} catch (error) {
		console.error(
			'Failed to remove token:',
			error instanceof Error ? error.message : 'Unknown error',
		);
		return false;
	}
};

// Helper: Get config directory path (useful for debugging/user info)
export const getConfigPath = (): string => {
	return getConfigDir();
};
