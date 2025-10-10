import {Box, Text} from 'ink';
import React from 'react';
import TextInput from 'ink-text-input';
// import Spinner from 'ink-spinner';
import {SignupData} from '../types/auth/index.js';

// Mock API Response Type
type ApiResponse<T> = {
	data: T | null;
	error: string | null;
	message: string;
};

// Mock API Functions
const mockCheckAuth = async (): Promise<ApiResponse<{isLoggedIn: boolean}>> => {
	return new Promise(resolve => {
		setTimeout(() => {
			// Change this to test different scenarios
			const isLoggedIn = false;
			resolve({
				data: {isLoggedIn},
				error: null,
				message: isLoggedIn ? 'User is already logged in' : 'No active session',
			});
		}, 1500);
	});
};

const mockSendOtp = async (
	_name: string,
	_email: string,
	_password: string,
): Promise<ApiResponse<{otpSent: boolean}>> => {
	return new Promise(resolve => {
		setTimeout(() => {
			resolve({
				data: {otpSent: true},
				error: null,
				message: 'Verification code sent successfully',
			});
		}, 2000);
	});
};

const mockVerifyOtp = async (
	_email: string,
	otp: string,
): Promise<ApiResponse<{verified: boolean; token?: string}>> => {
	return new Promise(resolve => {
		setTimeout(() => {
			const isValid = otp === '123456'; // Mock validation
			if (isValid) {
				resolve({
					data: {verified: true, token: 'mock-jwt-token'},
					error: null,
					message: 'Account created successfully',
				});
			} else {
				resolve({
					data: null,
					error: 'Invalid verification code',
					message: 'Verification failed',
				});
			}
		}, 1500);
	});
};

type SignupStep =
	| 'checking'
	| 'already-logged-in'
	| 'name'
	| 'email'
	| 'password'
	| 'sending-otp'
	| 'otp'
	| 'verifying'
	| 'success'
	| 'error';

export const Signup: React.FC = () => {
	const [step, setStep] = React.useState<SignupStep>('checking');
	const [signupData, setSignupData] = React.useState<SignupData>({
		name: '',
		email: '',
		password: '',
		otp: '',
	});

	const handleInputChange = (filed: keyof SignupData, value: string) => {
		setSignupData(prev => ({...prev, [filed]: value}));
	};

	const [errorMessage, setErrorMessage] = React.useState<string>('');

	// Check auth status on mount
	React.useEffect(() => {
		const checkAuth = async () => {
			const response = await mockCheckAuth();
			if (response.data?.isLoggedIn) {
				setStep('already-logged-in');
			} else {
				setStep('name');
			}
		};
		checkAuth();
	}, []);

	const handleNameSubmit = (value: string) => {
		// setSignupData(prev => ({...prev, name: value}));
		setStep('email');
	};

	const handleEmailSubmit = (value: string) => {
		// setSignupData(prev => ({...prev, email: value}));
		setStep('password');
	};

	const handlePasswordSubmit = async (value: string) => {
		// setSignupData(prev => ({...prev, password: value}));
		setStep('sending-otp');

		const response = await mockSendOtp(
			signupData.name,
			signupData.email,
			value,
		);

		if (response.error) {
			setErrorMessage(response.error);
			setStep('error');
		} else {
			setStep('otp');
		}
	};

	const handleOtpSubmit = async (value: string) => {
		setSignupData(prev => ({...prev, otp: value}));
		setStep('verifying');

		const response = await mockVerifyOtp(signupData.email, value);

		if (response.error) {
			setErrorMessage(response.error);
			setStep('error');
		} else {
			setStep('success');
		}
	};

	// Render based on current step
	if (step === 'checking') {
		return (
			<Box flexDirection="column" marginTop={1}>
				<Box>
					<Text color="cyan">{/* <Spinner type="dots" /> */}</Text>
					<Text> Checking for configuration and active sessions...</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'already-logged-in') {
		return (
			<Box flexDirection="column" marginTop={1}>
				<Text color="green">You are already logged in.</Text>
				<Text>
					Run <Text color="cyan">wosh --help</Text> to show all commands.
				</Text>
				<Text>
					Click <Text color="blue">https://me.com</Text> for docs
				</Text>
			</Box>
		);
	}

	if (step === 'name') {
		return (
			<Box flexDirection="column" marginTop={1}>
				<Text color="cyan" bold>
					Welcome to wosh. Let's get you onboard
				</Text>
				<Box marginTop={1} flexDirection="row">
					<Text>Name: </Text>
					<TextInput
						value={signupData.name}
						onSubmit={handleNameSubmit}
						// onChange={() => {}}
						onChange={value => handleInputChange('name', value)}
					/>
				</Box>
			</Box>
		);
	}

	if (step === 'email') {
		return (
			<Box flexDirection="column" marginTop={1}>
				<Text color="cyan" bold>
					Welcome to wosh. Let's get you onboard
				</Text>
				<Box marginTop={1}>
					<Text>Name: {signupData.name}</Text>
				</Box>
				<Box marginTop={1} flexDirection="row">
					<Text>Email: </Text>
					<TextInput
						value={signupData.email}
						onSubmit={handleEmailSubmit}
						// onChange={() => {}}
						onChange={value => handleInputChange('email', value)}
					/>
				</Box>
			</Box>
		);
	}

	if (step === 'password') {
		return (
			<Box flexDirection="column" marginTop={1}>
				<Text color="cyan" bold>
					Welcome to wosh. Let's get you onboard
				</Text>
				<Box marginTop={1}>
					<Text>Name: {signupData.name}</Text>
				</Box>
				<Box marginTop={1}>
					<Text>Email: {signupData.email}</Text>
				</Box>
				<Box marginTop={1} flexDirection="row">
					<Text>Password: </Text>
					<TextInput
						value={signupData.password}
						onSubmit={handlePasswordSubmit}
						onChange={value =>
							// setSignupData(prev => ({...prev, password: value}))
							handleInputChange('password', value)
						}
						mask="*"
					/>
				</Box>
			</Box>
		);
	}

	if (step === 'sending-otp') {
		return (
			<Box flexDirection="column" marginTop={1}>
				<Box>
					<Text color="cyan">{/* <Spinner type="dots" /> */}</Text>
					<Text> Sending verification code on {signupData.email}...</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'otp') {
		return (
			<Box flexDirection="column" marginTop={1}>
				<Text color="green">Verification code sent!</Text>
				<Box marginTop={1} flexDirection="row">
					<Text>Code: </Text>
					<TextInput
						value={signupData.otp}
						onSubmit={handleOtpSubmit}
						onChange={value => handleInputChange('otp', value)}
					/>
				</Box>
				<Box marginTop={1}>
					<Text dimColor>(Use 123456 for testing)</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'verifying') {
		return (
			<Box flexDirection="column" marginTop={1}>
				<Box>
					<Text color="cyan">{/* <Spinner type="dots" /> */}</Text>
					<Text> Verifying code...</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'success') {
		return (
			<Box flexDirection="column" marginTop={1}>
				<Text color="green" bold>
					Success!
				</Text>
				<Box marginTop={1}>
					<Text>
						Run <Text color="cyan">wosh --help</Text> for all commands.
					</Text>
				</Box>
				<Box marginTop={1}>
					<Text>
						Check out the docs at <Text color="blue">https://me.com</Text>
					</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'error') {
		return (
			<Box flexDirection="column" marginTop={1}>
				<Box borderStyle="round" borderColor="red" paddingX={1}>
					<Box flexDirection="column">
						<Text color="red" bold>
							Something went wrong
						</Text>
						<Text color="red">{errorMessage}</Text>
					</Box>
				</Box>
			</Box>
		);
	}

	return null;
};
