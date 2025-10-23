import {Box, Text} from 'ink';
import React from 'react';
import {getCLIToken, decryptCLIToken} from '../utils/token/utils.cliToken.js';
import {isAuthenticated} from '../hooks/auth/useAuth.js';

type CLITokenInfoStep =
	| 'checking-auth'
	| 'loading'
	| 'success'
	| 'error'
	| 'no-token';

interface TokenData {
	organization: string;
	project: string;
	hasPin: boolean;
}

export const CLITokenInfo: React.FC = () => {
	const [step, setStep] = React.useState<CLITokenInfoStep>('checking-auth');
	const [tokenData, setTokenData] = React.useState<TokenData | null>(null);
	const [errorMessage, setErrorMessage] = React.useState<string>('');

	React.useEffect(() => {
		const loadTokenInfo = async () => {
			try {
				// Step 1: Check authentication
				setStep('checking-auth');
				const isUserAuthenticated = await isAuthenticated();

				if (!isUserAuthenticated) {
					setErrorMessage(
						'You must be logged in to view CLI token information',
					);
					setStep('error');
					return;
				}

				// Step 2: Load token from device storage
				setStep('loading');
				const encryptedToken = await getCLIToken();

				if (!encryptedToken) {
					setStep('no-token');
					return;
				}

				// Step 3: Decrypt token
				const decryptResult = await decryptCLIToken({token: encryptedToken});

				if (decryptResult.error || !decryptResult.data) {
					setErrorMessage(
						decryptResult.message || 'Failed to decrypt CLI token',
					);
					setStep('error');
					return;
				}

				// Step 4: Extract and set token data
				setTokenData({
					organization: decryptResult.data.orgInfo.name,
					project: decryptResult.data.projectInfo.name,
					hasPin: !!decryptResult.data.pin,
				});
				setStep('success');
			} catch (error) {
				setErrorMessage(
					error instanceof Error
						? error.message
						: 'An unexpected error occurred while loading token information',
				);
				setStep('error');
			}
		};

		void loadTokenInfo();
	}, []);

	// Render checking authentication state
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

	// Render loading state
	if (step === 'loading') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Loading CLI token information...</Text>
				</Box>
			</Box>
		);
	}

	// Render no token state
	if (step === 'no-token') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box borderStyle="round" borderColor="yellow" paddingX={1}>
					<Box flexDirection="column">
						<Text color="yellow" bold>
							⚠ No CLI Token Found
						</Text>
						<Text color="yellow">You haven't set up a CLI token yet.</Text>
					</Box>
				</Box>
				<Box marginTop={1}>
					<Text>
						Use <Text color="cyan">wosh auth cli</Text> to set up a CLI token.
					</Text>
				</Box>
			</Box>
		);
	}

	// Render error state
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
						Setup: <Text color="cyan">wosh auth cli</Text>
					</Text>
				</Box>
			</Box>
		);
	}

	// Render success state with token information
	if (step === 'success' && tokenData) {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box borderStyle="round" borderColor="green" paddingX={1} paddingY={1}>
					<Box flexDirection="column">
						<Text color="green" bold>
							✓ CLI Information
						</Text>
						<Box marginTop={1} flexDirection="column">
							<Box>
								<Text color="cyan" bold>
									Organization:{' '}
								</Text>
								<Text>{tokenData.organization}</Text>
							</Box>
							<Box>
								<Text color="cyan" bold>
									Project:{' '}
								</Text>
								<Text>{tokenData.project}</Text>
							</Box>
						</Box>
					</Box>
				</Box>
				<Box marginTop={1}>
					<Text dimColor>
						This token is securely stored and encrypted on your device.
					</Text>
				</Box>
				<Box marginTop={1}>
					<Text>
						Revoke token: <Text color="cyan">wosh auth cli revoke</Text>
					</Text>
				</Box>
			</Box>
		);
	}

	return null;
};
