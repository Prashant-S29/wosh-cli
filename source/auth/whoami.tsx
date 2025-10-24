import {Box, Text} from 'ink';
import React from 'react';
import {
	getSessionToken,
	removeSessionToken,
} from '../utils/token/utils.sessionToken.js';
import {GetSessionResponse} from '../types/auth/index.js';
import {SafeApiResponse} from '../types/index.js';

type WhoamiStep =
	| 'checking'
	| 'not-logged-in'
	| 'fetching'
	| 'success'
	| 'error';

export const Whoami: React.FC = () => {
	const [step, setStep] = React.useState<WhoamiStep>('checking');
	const [sessionData, setSessionData] =
		React.useState<GetSessionResponse | null>(null);
	const [errorMessage, setErrorMessage] = React.useState<string>('');

	React.useEffect(() => {
		const fetchProfile = async () => {
			// Step 1: Check if token exists
			const token = await getSessionToken();

			if (!token) {
				setStep('not-logged-in');
				return;
			}

			// Step 2: Fetch session data
			setStep('fetching');

			try {
				const sessionResponse = await fetch(
					`${process.env['BACKEND_BASE_URL']}/api/auth/session`,
					{
						method: 'GET',
						headers: {
							'Content-Type': 'application/json',
							Authorization: `Bearer ${token}`,
						},
					},
				);

				if (!sessionResponse.ok) {
					setErrorMessage('Session expired or invalid. Please log in again.');
					setStep('error');
					return;
				}

				const sessionResult =
					(await sessionResponse.json()) as SafeApiResponse<GetSessionResponse>;

				// Step 3: Check if we got valid data
				if (!sessionResult.data?.session?.id || !sessionResult.data?.user?.id) {
					setErrorMessage('Invalid session. Please log in again.');
					setStep('error');
					removeSessionToken();
					return;
				}

				// Step 4: Success
				setSessionData(sessionResult.data);
				setStep('success');
			} catch (error) {
				console.error('Whoami error:', error);
				setErrorMessage(
					error instanceof Error ? error.message : 'Network error',
				);
				removeSessionToken();
				setStep('error');
			}
		};

		void fetchProfile();
	}, []);

	// Render based on current step
	if (step === 'checking') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Checking authentication status...</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'not-logged-in') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Text color="yellow">⚠ You are not logged in.</Text>
				<Box marginTop={1}>
					<Text>
						Run <Text color="cyan">wosh auth signup</Text> to create an account.
					</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'fetching') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Fetching profile...</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'success' && sessionData) {
		const userName =
			sessionData.user.name || sessionData.user.email.split('@')[0];
		const userEmail = sessionData.user.email;

		return (
			<Box flexDirection="column" marginY={1}>
				<Text color="cyan">Username: {userName}</Text>
				<Text color="gray">Email: {userEmail}</Text>
			</Box>
		);
	}

	if (step === 'error') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box borderStyle="round" borderColor="red" paddingX={1}>
					<Box flexDirection="column">
						<Text color="red" bold>
							✗ Something went wrong
						</Text>
						<Text color="red">{errorMessage}</Text>
					</Box>
				</Box>
				<Box marginTop={1}>
					<Text>
						Run <Text color="cyan">wosh auth signup</Text> to log in again.
					</Text>
				</Box>
			</Box>
		);
	}

	return null;
};
