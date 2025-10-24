import {Box, Text} from 'ink';
import React from 'react';
import TextInput from 'ink-text-input';
import {SignupData} from '../types/auth/index.js';
import {saveSessionToken} from '../utils/token/utils.sessionToken.js';
import {isAuthenticated} from '../hooks/auth/useAuth.js';
import {useTypedMutation} from '../hooks/api/useTypedMutation.js';

// API Request/Response Types
type SignupRequest = {
	email: string;
};

type SignupOtpResponse = {
	success: boolean;
};

type VerifyOtpRequest = {
	email: string;
	otp: string;
};

type VerifyOtpResponse = {
	token: string;
	verified: boolean;
};

type SignupStep =
	| 'checking'
	| 'already-logged-in'
	| 'email'
	| 'sending-otp'
	| 'otp'
	| 'verifying'
	| 'success'
	| 'error';

interface SignupProps {
	mode: 'signup' | 'login';
}
export const Signup: React.FC<SignupProps> = ({mode}) => {
	const [step, setStep] = React.useState<SignupStep>('checking');
	const [signupData, setSignupData] = React.useState<SignupData>({
		email: '',
		otp: '',
	});
	const [errorMessage, setErrorMessage] = React.useState<string>('');

	// Mutations
	const reqSignUpOtpMutation = useTypedMutation<
		SignupRequest,
		SignupOtpResponse
	>({
		endpoint: '/api/auth/req-signup-otp',
	});

	const verifyOtpMutation = useTypedMutation<
		VerifyOtpRequest,
		VerifyOtpResponse
	>({
		endpoint: '/api/auth/signup-with-email-otp',
	});

	const handleInputChange = (field: keyof SignupData, value: string) => {
		setSignupData(prev => ({...prev, [field]: value}));
	};

	// Check auth status on mount
	React.useEffect(() => {
		const checkAuthStatus = async () => {
			const authenticated = await isAuthenticated();
			if (authenticated) {
				setStep('already-logged-in');
			} else {
				setStep('email');
			}
		};
		void checkAuthStatus();
	}, []);

	const handleEmailSubmit = async (value: string) => {
		if (!value.includes('@')) {
			setErrorMessage('Please enter a valid email');
			setStep('error');
			return;
		}

		handleInputChange('email', value);
		setStep('sending-otp');

		try {
			const response = await reqSignUpOtpMutation.mutateAsync({
				email: value,
			});

			if (response.error || !response.data?.success) {
				setErrorMessage(response.error?.message || 'Failed to send OTP');
				setStep('error');
			} else {
				setStep('otp');
			}
		} catch (error) {
			setErrorMessage(error instanceof Error ? error.message : 'Network error');
			setStep('error');
		}
	};

	const handleOtpSubmit = async (value: string) => {
		if (value.length !== 6) {
			setErrorMessage('Please enter a valid 6-digit code');
			setStep('error');
			return;
		}

		handleInputChange('otp', value);
		setStep('verifying');

		try {
			const response = await verifyOtpMutation.mutateAsync({
				email: signupData.email,
				otp: value,
			});

			if (response.error || !response.data?.token) {
				setErrorMessage(response.error?.message || 'Verification failed');
				setStep('error');
			} else {
				// Save token securely
				const tokenSaved = await saveSessionToken(response.data.token);
				if (tokenSaved) {
					setStep('success');
				} else {
					setErrorMessage('Failed to save authentication token');
					setStep('error');
				}
			}
		} catch (error) {
			setErrorMessage(error instanceof Error ? error.message : 'Network error');
			setStep('error');
		}
	};

	// Render based on current step
	if (step === 'checking') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Checking for configuration and active sessions...</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'already-logged-in') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Text color="green">✓ You are already logged in.</Text>
				<Box marginTop={1}>
					<Text>
						Run <Text color="cyan">wosh --help</Text> to show all commands.
					</Text>
				</Box>
				<Box>
					<Text>
						Visit <Text color="blue">https://wosh.dev/docs</Text> for
						documentation.
					</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'email') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Text color="cyan" bold>
					Welcome to Wosh
				</Text>
				<Text>
					{mode === 'signup'
						? "Let's get you set up with your account."
						: 'Login to your account.'}
				</Text>
				<Box marginTop={1} flexDirection="row">
					<Text>Email: </Text>
					<TextInput
						value={signupData.email}
						placeholder="you@example.com"
						onSubmit={handleEmailSubmit}
						onChange={value => handleInputChange('email', value)}
					/>
				</Box>
			</Box>
		);
	}

	if (step === 'sending-otp') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Sending verification code to {signupData.email}...</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'otp') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Text color="green">✓ Verification code sent!</Text>
				<Box marginTop={1}>
					<Text>Enter the 6-digit code sent to:</Text>
					<Text color="blue"> {signupData.email}</Text>
				</Box>
				<Box marginTop={1} flexDirection="row">
					<Text>Code: </Text>
					<TextInput
						value={signupData.otp}
						placeholder="000000"
						onSubmit={handleOtpSubmit}
						onChange={value => handleInputChange('otp', value)}
						mask="*"
					/>
				</Box>
			</Box>
		);
	}

	if (step === 'verifying') {
		return (
			<Box flexDirection="column" marginY={1}>
				<Box>
					<Text color="cyan">⠙</Text>
					<Text> Verifying your code...</Text>
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
						{mode === 'signup'
							? "Your account has been created and you're now logged in."
							: "You're now logged in."}
					</Text>
				</Box>
				<Box marginTop={1}>
					<Text>
						Run <Text color="cyan">wosh --help</Text> to see all available
						commands.
					</Text>
				</Box>
				<Box marginTop={1}>
					<Text>
						Check out the docs at{' '}
						<Text color="blue">https://wosh.dev/docs</Text>
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
