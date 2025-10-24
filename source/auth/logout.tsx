import {Box, Text} from 'ink';
import React from 'react';
import {
	getSessionToken,
	removeSessionToken,
} from '../utils/token/utils.sessionToken.js';
import {useTypedMutation} from '../hooks/api/useTypedMutation.js';
import {GetSessionResponse} from '../types/auth/index.js';
import {SafeApiResponse} from '../types/index.js';

type SignoutResponse = {
	success: boolean;
	message?: string;
};

type LogoutStep =
	| 'checking'
	| 'not-logged-in'
	| 'verifying'
	| 'signing-out'
	| 'success'
	| 'error';

export const Logout: React.FC = () => {
	const [step, setStep] = React.useState<LogoutStep>('checking');
	const [errorMessage, setErrorMessage] = React.useState<string>('');

	// Mutation for signing out
	const signoutMutation = useTypedMutation<void, SignoutResponse>({
		endpoint: '/api/auth/signout',
		method: 'POST',
	});

	// Check auth and logout on mount
	React.useEffect(() => {
		const performLogout = async () => {
			// Step 1: Check if token exists
			const token = await getSessionToken();

			if (!token) {
				setStep('not-logged-in');
				return;
			}

			setStep('verifying');

			try {
				// Step 2: Verify token with backend
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

				// Step 3: Check if token is valid
				if (!sessionResponse.ok) {
					// Token is expired or invalid, simply delete it
					removeSessionToken();
					setStep('success');
					return;
				}

				const sessionData =
					(await sessionResponse.json()) as SafeApiResponse<GetSessionResponse>;

				// Step 4: Verify we got valid session data
				if (!sessionData?.data?.session?.id || !sessionData?.data?.user?.id) {
					// Token is invalid, simply delete it
					removeSessionToken();
					setStep('success');
					return;
				}

				// Step 5: Token is valid, make signout request
				setStep('signing-out');

				try {
					const signoutResponse = await signoutMutation.mutateAsync(undefined);

					if (signoutResponse.error || !signoutResponse.data?.success) {
						setErrorMessage(
							signoutResponse.error?.message || 'Failed to sign out',
						);
						setStep('error');
						return;
					}

					// Step 6: Signout successful, remove token
					removeSessionToken();
					setStep('success');
				} catch (error) {
					setErrorMessage(
						error instanceof Error ? error.message : 'Network error',
					);
					setStep('error');
				}
			} catch (error) {
				console.error('Logout error:', error);
				setErrorMessage(
					error instanceof Error ? error.message : 'Network error',
				);
				setStep('error');
			}
		};

		void performLogout();
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

	if (step === 'verifying') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Verifying your session...</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'signing-out') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Signing you out...</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'success') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Text color="green" bold>
					✓ Logged out successfully
				</Text>
				<Box marginTop={1}>
					<Text>
						Run <Text color="cyan">wosh auth signup</Text> to log back in.
					</Text>
				</Box>
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
			</Box>
		);
	}

	return null;
};
