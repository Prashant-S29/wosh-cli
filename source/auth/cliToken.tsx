import {Box, Text} from 'ink';
import React from 'react';
import {
	saveCLIToken,
	getCLIToken,
	removeCLIToken,
	isValidCLITokenFormat,
	getEncryptedCLITokenBlob,
} from '../utils/token/utils.cliToken.js';
import {getAuth} from '../utils/auth/getAuth.js';

type CLITokenStep =
	| 'checking'
	| 'token-exists'
	| 'validating'
	| 'success'
	| 'warning';

interface CLITokenProps {
	mode: 'set' | 'revoke';
	token?: string; // Add token prop
}

export const CLIToken: React.FC<CLITokenProps> = ({
	mode,
	token: providedToken,
}) => {
	const [step, setStep] = React.useState<CLITokenStep>('checking');
	const [warningMessage, setWarningMessage] = React.useState<string>('');

	// Process token on mount
	React.useEffect(() => {
		const processToken = async () => {
			if (mode === 'revoke') {
				// For revoke mode, directly proceed to remove token
				const existingToken = await getEncryptedCLITokenBlob();
				if (existingToken) {
					const removed = removeCLIToken();
					if (removed) {
						setStep('success');
					} else {
						setWarningMessage('Failed to remove CLI token');
						setStep('warning');
					}
				} else {
					setWarningMessage('No CLI token found to revoke');
					setStep('warning');
				}
			} else {
				// For set mode
				if (!providedToken) {
					setWarningMessage(
						'Token is required. Usage: wosh auth cli token=<your-token>',
					);
					setStep('warning');
					return;
				}

				const {isAuthenticated} = await getAuth();

				// Check user is authenticated
				if (!isAuthenticated) {
					setWarningMessage('Please login to continue');
					setStep('warning');
					return;
				}

				// Check if token already exists
				const existingToken = await getCLIToken();
				if (existingToken && isValidCLITokenFormat(existingToken)) {
					setStep('token-exists');
					return;
				}

				const trimmedValue = providedToken.trim();

				// Validate token format
				if (!isValidCLITokenFormat(trimmedValue)) {
					setWarningMessage(
						'Invalid CLI token. Please check the token and try again',
					);
					setStep('warning');
					return;
				}

				setStep('validating');

				// Save token
				const tokenSaved = await saveCLIToken(trimmedValue);
				if (tokenSaved) {
					setStep('success');
				} else {
					setWarningMessage('Failed to save CLI token');
					setStep('warning');
				}
			}
		};
		void processToken();
	}, [mode, providedToken]);

	// Render based on current step
	if (step === 'checking') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text>
						{' '}
						{mode === 'revoke' ? 'Removing' : 'Processing'} CLI token...
					</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'token-exists') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Text>CLI token is already set</Text>
				<Box marginTop={1}>
					<Text>
						Run <Text color="cyan">wosh auth cli revoke</Text> to remove the
						token
					</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'validating') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Validating CLI token...</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'success') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Text color="green" bold>
					✓ Success!
				</Text>
				<Box marginTop={1}>
					<Text>
						{mode === 'revoke'
							? 'CLI token has been removed successfully.'
							: 'CLI token has been saved successfully.'}
					</Text>
				</Box>
				<Box marginTop={1}>
					<Text>
						Run <Text color="cyan">wosh --help</Text> to see all available
						commands.
					</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'warning') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box borderStyle="round" borderColor="yellow" paddingX={1}>
					<Box flexDirection="column">
						<Text color="yellow" bold>
							⚠ Warning
						</Text>
						<Text color="yellow">{warningMessage}</Text>
					</Box>
				</Box>
				{mode === 'set' && (
					<Box marginTop={1}>
						<Text dimColor>
							Please check your token and try again, or contact support if the
							issue persists.
						</Text>
					</Box>
				)}
			</Box>
		);
	}

	return null;
};
