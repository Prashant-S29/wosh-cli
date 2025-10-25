import {Box, Text} from 'ink';
import React from 'react';
import {getCLIToken, decryptCLIToken} from '../utils/token/utils.cliToken.js';
import {useTypedQuery} from '../hooks/api/useTypedQuery.js';
import {
	GetOrganizationResponse,
	GetProjectResponse,
} from '../types/api/request/index.js';
import {getAuth} from '../utils/auth/getAuth.js';

type CLITokenInfoStep =
	| 'checking-auth'
	| 'loading-token'
	| 'loading-details'
	| 'success'
	| 'error'
	| 'no-token';

interface TokenData {
	organization: string;
	project: string;
	hasPin: boolean;
}

interface DecryptedToken {
	masterPassphrase: string;
	pin?: string;
	orgId: string;
	projectId: string;
}

export const CLITokenInfo: React.FC = () => {
	const [step, setStep] = React.useState<CLITokenInfoStep>('checking-auth');
	const [tokenData, setTokenData] = React.useState<TokenData | null>(null);
	const [errorMessage, setErrorMessage] = React.useState<string>('');
	const [decryptedToken, setDecryptedToken] =
		React.useState<DecryptedToken | null>(null);

	// Fetch organization info
	const {data: organizationData, isLoading: isOrganizationLoading} =
		useTypedQuery<GetOrganizationResponse>({
			endpoint: `/api/organization/${decryptedToken?.orgId}`,
			queryKey: ['organization', decryptedToken?.orgId],
			enabled: !!decryptedToken?.orgId,
		});

	// Fetch project info
	const {data: projectData, isLoading: isProjectLoading} =
		useTypedQuery<GetProjectResponse>({
			endpoint: `/api/project/${decryptedToken?.orgId}/${decryptedToken?.projectId}`,
			queryKey: ['project', decryptedToken?.projectId],
			enabled: !!decryptedToken?.projectId,
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
				const decryptResult = await decryptCLIToken(encryptedToken);

				if (decryptResult.error || !decryptResult.data) {
					setErrorMessage(
						decryptResult.message || 'Failed to decrypt CLI token',
					);
					setStep('error');
					return;
				}

				// Store decrypted data and trigger queries
				setDecryptedToken(decryptResult.data);
				setStep('loading-details');
			} catch (error) {
				setErrorMessage(
					error instanceof Error
						? error.message
						: 'An unexpected error occurred while loading token information',
				);
				setStep('error');
			}
		};

		void loadAndDecryptToken();
	}, []);

	// Handle query results and exit
	React.useEffect(() => {
		if (step !== 'loading-details' || !decryptedToken) {
			return;
		}

		// Wait for queries to complete
		if (isOrganizationLoading || isProjectLoading) {
			return;
		}

		// Handle errors
		if (organizationData?.error || !organizationData?.data) {
			setErrorMessage(
				organizationData?.message || 'Failed to fetch organization',
			);
			setStep('error');
			return;
		}

		if (projectData?.error || !projectData?.data) {
			setErrorMessage(projectData?.message || 'Failed to fetch project');
			setStep('error');
			return;
		}

		// Success - set data and schedule exit
		setTokenData({
			organization: organizationData.data.name,
			project: projectData.data.name,
			hasPin: !!decryptedToken.pin,
		});
		setStep('success');
	}, [
		step,
		decryptedToken,
		isOrganizationLoading,
		isProjectLoading,
		organizationData,
		projectData,
	]);

	// Auto-exit after showing success or error
	React.useEffect(() => {
		if (step === 'success' || step === 'error' || step === 'no-token') {
			const timer = setTimeout(() => {
				process.exit(step === 'success' || step === 'no-token' ? 0 : 1);
			}, 100);

			return () => clearTimeout(timer);
		}

		return () => {};
	}, [step]);

	// Render functions for cleaner code
	const renderCheckingAuth = () => (
		<Box flexDirection="column" marginY={1}>
			<Box>
				<Text color="cyan">⠙</Text>
				<Text> Verifying authentication...</Text>
			</Box>
		</Box>
	);

	const renderLoading = () => (
		<Box flexDirection="column" marginY={1}>
			<Box>
				<Text color="cyan">⠙</Text>
				<Text> Loading CLI token information...</Text>
			</Box>
		</Box>
	);

	const renderNoToken = () => (
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
					Use <Text color="cyan">wosh auth cli --token={'<token>'}</Text> to set
					up a CLI token.
				</Text>
			</Box>
		</Box>
	);

	const renderError = () => (
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

	const renderSuccess = () =>
		tokenData && (
			<Box flexDirection="column" marginY={1}>
				<Box borderStyle="round" borderColor="green" paddingX={1} paddingY={1}>
					<Box flexDirection="column">
						<Text color="green" bold>
							✓ CLI Token Information
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

	// Main render logic
	switch (step) {
		case 'checking-auth':
			return renderCheckingAuth();
		case 'loading-token':
		case 'loading-details':
			return renderLoading();
		case 'no-token':
			return renderNoToken();
		case 'error':
			return renderError();
		case 'success':
			return renderSuccess();
		default:
			return null;
	}
};
