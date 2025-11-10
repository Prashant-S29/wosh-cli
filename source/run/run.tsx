import {Box, Text} from 'ink';
import React from 'react';
import {spawn} from 'child_process';
import {getCLIToken, decryptCLIToken} from '../utils/token/utils.cliToken.js';
import {useTypedQuery} from '../hooks/api/useTypedQuery.js';
import {GetAllSecretsResponse} from '../types/api/request/index.js';
import {getAuth} from '../utils/auth/getAuth.js';
import {
	decryptSecretsArray,
	secureWipeSecrets,
} from '../utils/secrets/decrypt.js';
import {recoverProjectKey} from '../utils/secrets/getProjectKeys.js';

type RunStep =
	| 'checking-auth'
	| 'loading-token'
	| 'decrypting-token'
	| 'fetching-secrets'
	| 'recovering-key'
	| 'decrypting-secrets'
	| 'injecting-secrets'
	| 'success'
	| 'error'
	| 'no-token'
	| 'no-command';

interface DecryptedToken {
	masterPassphrase: string;
	pin?: string;
	orgId: string;
	projectId: string;
}

interface DecryptedSecret {
	key: string;
	value: string;
	note?: string | null;
}

interface RunProps {
	command?: string;
	watch?: boolean;
}

export const Run: React.FC<RunProps> = ({command, watch = false}) => {
	const [step, setStep] = React.useState<RunStep>('checking-auth');
	const [errorMessage, setErrorMessage] = React.useState<string>('');
	const [decryptedToken, setDecryptedToken] =
		React.useState<DecryptedToken | null>(null);
	const [decryptedSecrets, setDecryptedSecrets] = React.useState<
		DecryptedSecret[] | null
	>(null);
	const [_, setChildProcessExitCode] = React.useState<
		number | null
	>(null);

	// Fetch all secrets (no pagination)
	const {
		data: secretsResponse,
		isLoading: isSecretsLoading,
		error: secretsError,
	} = useTypedQuery<GetAllSecretsResponse>({
		endpoint: `/api/secret?projectId=${decryptedToken?.projectId}`,
		queryKey: ['secrets', decryptedToken?.projectId],
		enabled: !!decryptedToken?.projectId && step === 'fetching-secrets',
	});

	// Initial authentication and token decryption
	React.useEffect(() => {
		const loadAndDecryptToken = async () => {
			try {
				// Check authentication
				const {isAuthenticated} = await getAuth();
				if (!isAuthenticated) {
					setErrorMessage(
						'You must be logged in to view CLI token information',
					);
					setStep('error');
					return;
				}

				// Load encrypted token
				setStep('loading-token');
				const encryptedToken = await getCLIToken();

				if (!encryptedToken) {
					setStep('no-token');
					return;
				}

				// Decrypt token
				setStep('decrypting-token');
				const decryptResult = await decryptCLIToken(encryptedToken);

				if (decryptResult.error || !decryptResult.data) {
					setErrorMessage(
						decryptResult.message || 'Failed to decrypt CLI token',
					);
					setStep('error');
					return;
				}

				// Store decrypted data and trigger secrets fetch
				setDecryptedToken(decryptResult.data);
				setStep('fetching-secrets');
			} catch (error) {
				setErrorMessage(
					error instanceof Error
						? error.message
						: 'An unexpected error occurred while loading token',
				);
				setStep('error');
			}
		};

		void loadAndDecryptToken();
	}, []);

	// Handle secrets fetch and decryption
	React.useEffect(() => {
		const processSecrets = async () => {
			if (step !== 'fetching-secrets' || !decryptedToken) {
				return;
			}

			// Wait for query to complete
			if (isSecretsLoading) {
				return;
			}

			// Handle query error
			if (secretsError) {
				setErrorMessage('Failed to fetch secrets');
				setStep('error');
				return;
			}

			// Handle API error response
			if (secretsResponse?.error || !secretsResponse?.data) {
				setErrorMessage(secretsResponse?.message || 'Failed to fetch secrets');
				setStep('error');
				return;
			}

			// If no secrets and no command, just show empty state
			if (secretsResponse.data.allSecrets.length === 0) {
				if (!command) {
					console.log('\n=== No Secrets Found ===');
					setDecryptedSecrets([]);
					setStep('success');
				} else {
					setDecryptedSecrets([]);
					setStep('injecting-secrets');
				}
				return;
			}

			try {
				// Recover project key
				setStep('recovering-key');
				const keyResult = await recoverProjectKey(
					{
						masterPassphrase: decryptedToken.masterPassphrase,
						pin: decryptedToken.pin,
					},
					decryptedToken.orgId,
					decryptedToken.projectId,
				);

				if (keyResult.error || !keyResult.data) {
					setErrorMessage(keyResult.message || 'Failed to recover project key');
					setStep('error');
					return;
				}

				// Decrypt secrets
				setStep('decrypting-secrets');
				const decryptResult = await decryptSecretsArray({
					encryptedSecrets: secretsResponse.data.allSecrets,
					projectKey: keyResult.data,
				});

				if (decryptResult.error || !decryptResult.data) {
					setErrorMessage(decryptResult.message || 'Failed to decrypt secrets');
					setStep('error');
					return;
				}

				// If no command provided, show full secrets
				if (!command) {
					console.log('\n=== CLI Token Data ===');
					console.log('Organization ID:', decryptedToken.orgId);
					console.log('Project ID:', decryptedToken.projectId);
					console.log('Has PIN:', !!decryptedToken.pin);

					console.log('\n=== Decrypted Secrets ===');
					console.log(`Total: ${decryptResult.data.length} secrets\n`);

					decryptResult.data.forEach((secret, index) => {
						console.log(`[${index + 1}] ${secret.key}`);
						console.log(`    Value: ${secret.value}`);
						if (secret.note) {
							console.log(`    Note: ${secret.note}`);
						}
						console.log('');
					});

					setDecryptedSecrets(decryptResult.data);
					setStep('success');
				} else {
					// Command provided, inject secrets
					setDecryptedSecrets(decryptResult.data);
					setStep('injecting-secrets');
				}
			} catch (error) {
				setErrorMessage(
					error instanceof Error
						? error.message
						: 'An unexpected error occurred during decryption',
				);
				setStep('error');
			}
		};

		void processSecrets();
	}, [
		step,
		decryptedToken,
		isSecretsLoading,
		secretsError,
		secretsResponse,
		command,
		watch,
	]);

	// Handle secret injection into child process
	React.useEffect(() => {
		if (step !== 'injecting-secrets' || !decryptedSecrets) {
			return;
		}

		// If no command, show error
		if (!command) {
			setStep('no-command');
			return;
		}

		try {
			// Build environment variables object
			const envWithSecrets = {
				...process.env,
			};

			// Inject secrets into environment
			decryptedSecrets.forEach(secret => {
				envWithSecrets[secret.key] = secret.value;
			});

			console.log(
				`\n✓ Injecting ${decryptedSecrets.length} secrets into environment`,
			);
			
			// Show secret keys being injected only if watch mode is enabled
			if (watch) {
				console.log('\nSecret keys being read:');
				decryptedSecrets.forEach((secret, index) => {
					console.log(`  [${index + 1}] ${secret.key}`);
				});
			}
			
			console.log(`\n✓ Running: ${command}\n`);

			// Parse command (handle both "npm run dev" and npm run dev)
			const cleanCommand = command.replace(/^["']|["']$/g, '');

			// Spawn child process with injected environment
			const childProcess = spawn(cleanCommand, {
				shell: true,
				stdio: 'inherit', // Pass through stdin, stdout, stderr
				env: envWithSecrets,
			});

			// Handle process exit
			childProcess.on('exit', code => {
				setChildProcessExitCode(code ?? 0);

				// Secure cleanup of secrets from memory
				secureWipeSecrets(decryptedSecrets);

				// Exit with same code as child process
				process.exit(code ?? 0);
			});

			// Handle process errors
			childProcess.on('error', error => {
				setErrorMessage(`Failed to execute command: ${error.message}`);
				setStep('error');

				// Secure cleanup
				secureWipeSecrets(decryptedSecrets);
			});

			// Handle SIGINT (Ctrl+C) to cleanup properly
			process.on('SIGINT', () => {
				childProcess.kill('SIGINT');
				secureWipeSecrets(decryptedSecrets);
				process.exit(130); // Standard exit code for SIGINT
			});

			// Handle SIGTERM
			process.on('SIGTERM', () => {
				childProcess.kill('SIGTERM');
				secureWipeSecrets(decryptedSecrets);
				process.exit(143); // Standard exit code for SIGTERM
			});
		} catch (error) {
			setErrorMessage(
				error instanceof Error
					? error.message
					: 'Failed to inject secrets into process',
			);
			setStep('error');

			// Secure cleanup
			if (decryptedSecrets) {
				secureWipeSecrets(decryptedSecrets);
			}
		}
	}, [step, decryptedSecrets, command, watch]);

	// Auto-exit and cleanup (only for non-command modes)
	React.useEffect(() => {
		if (
			step === 'success' ||
			step === 'error' ||
			step === 'no-token' ||
			step === 'no-command' ||
			step === 'injecting-secrets'
		) {
			// Secure cleanup
			if (decryptedSecrets) {
				secureWipeSecrets(decryptedSecrets);
			}

			// Don't auto-exit if we're running a command
			if (step === 'injecting-secrets') {
				return;
			}

			const timer = setTimeout(() => {
				process.exit(step === 'success' || step === 'no-token' ? 0 : 1);
			}, 100);

			return () => clearTimeout(timer);
		}

		return () => {};
	}, [step, decryptedSecrets]);

	// Render checking authentication
	if (step === 'checking-auth') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Verifying authentication...</Text>
				</Box>
			</Box>
		);
	}

	// Render loading token
	if (step === 'loading-token') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Loading CLI token...</Text>
				</Box>
			</Box>
		);
	}

	// Render decrypting token
	if (step === 'decrypting-token') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Decrypting CLI token...</Text>
				</Box>
			</Box>
		);
	}

	// Render fetching secrets
	if (step === 'fetching-secrets') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Fetching secrets from server...</Text>
				</Box>
			</Box>
		);
	}

	// Render recovering project key
	if (step === 'recovering-key') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Recovering project key...</Text>
				</Box>
			</Box>
		);
	}

	// Render decrypting secrets
	if (step === 'decrypting-secrets') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Decrypting secrets...</Text>
				</Box>
			</Box>
		);
	}

	// Render injecting secrets (this will be shown briefly before child process takes over)
	if (step === 'injecting-secrets') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Injecting secrets into environment...</Text>
				</Box>
			</Box>
		);
	}

	// Render no command error
	if (step === 'no-command') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box borderStyle="round" borderColor="yellow" paddingX={1}>
					<Box flexDirection="column">
						<Text color="yellow" bold>
							⚠ No Command Provided
						</Text>
						<Text color="yellow">
							Please provide a command to run with injected secrets.
						</Text>
					</Box>
				</Box>
				<Box marginTop={1}>
					<Text>
						Usage: <Text color="cyan">wosh run --command="npm run dev"</Text>
					</Text>
				</Box>
			</Box>
		);
	}

	// Render no token found
	if (step === 'no-token') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box borderStyle="round" borderColor="yellow" paddingX={1}>
					<Box flexDirection="column">
						<Text color="yellow" bold>
							⚠ No CLI Token Found
						</Text>
						<Text color="yellow">
							You need to set up a CLI token before running commands.
						</Text>
					</Box>
				</Box>
				<Box marginTop={1}>
					<Text>
						Setup: <Text color="cyan">wosh auth cli --token={'<token>'}</Text>
					</Text>
				</Box>
			</Box>
		);
	}

	// Render error
	if (step === 'error') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box borderStyle="round" borderColor="red" paddingX={1}>
					<Box flexDirection="column">
						<Text color="red" bold>
							✗ Error
						</Text>
						<Text color="red">{errorMessage}</Text>
					</Box>
				</Box>
				<Box marginTop={1}>
					<Text dimColor>
						If this issue persists, try revoking and setting up a new CLI token.
					</Text>
				</Box>
				<Box marginTop={1}>
					<Text>
						Revoke: <Text color="cyan">wosh auth cli revoke</Text>
					</Text>
				</Box>
				<Box>
					<Text>
						Setup: <Text color="cyan">wosh auth cli --token={'<token>'}</Text>
					</Text>
				</Box>
			</Box>
		);
	}

	// Render success (only shown when no command provided)
	if (step === 'success') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box borderStyle="round" borderColor="green" paddingX={1} paddingY={1}>
					<Box flexDirection="column">
						<Text color="green" bold>
							✓ Secrets Decrypted Successfully
						</Text>
						<Box marginTop={1}>
							<Text>
								Total secrets:{' '}
								<Text color="cyan">{decryptedSecrets?.length ?? 0}</Text>
							</Text>
						</Box>
						<Box marginTop={1}>
							<Text dimColor>Check console output above for all secrets</Text>
						</Box>
					</Box>
				</Box>
			</Box>
		);
	}

	return null;
};