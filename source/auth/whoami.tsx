import React, {useState, useEffect} from 'react';
import {Box, Text} from 'ink';
import fs from 'fs/promises';
import {existsSync} from 'fs';
import os from 'os';
import path from 'path';

type ApiResponse<T> = {
	data: T | null;
	error: string | null;
	message: string;
};

type UserProfile = {
	id: string;
	name: string;
	email: string;
};

type FlowStep = 'loading' | 'success' | 'error' | 'not-logged-in';

const CONFIG_DIR = path.join(os.homedir(), '.wosh');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

// Mock API to fetch profile - replace with real implementation
const mockFetchProfile = async (
	token: string,
): Promise<ApiResponse<UserProfile>> => {
	console.log(token);

	await new Promise(resolve => setTimeout(resolve, 1200));

	// Simulate success
	return {
		data: {
			id: 'usr_12345',
			name: 'John Doe',
			email: 'john@example.com',
		},
		error: null,
		message: 'Profile fetched successfully',
	};
};

export const Whoami: React.FC = () => {
	const [step, setStep] = useState<FlowStep>('loading');
	const [profile, setProfile] = useState<UserProfile | null>(null);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		fetchProfile();
	}, []);

	const fetchProfile = async () => {
		try {
			// Check if config exists
			if (!existsSync(CONFIG_FILE)) {
				setStep('not-logged-in');
				process.exit(0);
			}

			// Read config
			const data = await fs.readFile(CONFIG_FILE, 'utf8');
			const config = JSON.parse(data);

			if (!config?.token) {
				setStep('not-logged-in');
				process.exit(0);
			}

			// Fetch profile using token
			const response = await mockFetchProfile(config.token);

			if (response.error || !response.data) {
				setError(response.message);
				setStep('error');
				setTimeout(() => process.exit(1), 2500);
			}

			setProfile(response.data);
			setStep('success');
			process.exit(0);
		} catch (err) {
			setError('Failed to fetch profile');
			setStep('error');
			setTimeout(() => process.exit(1), 2500);
		}
	};

	if (step === 'loading') {
		return (
			<Box flexDirection="column" marginTop={1}>
				<Box>
					<Text color="cyan"></Text>
					<Text> fetching profile....</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'not-logged-in') {
		return (
			<Box flexDirection="column" marginTop={1}>
				<Text color="yellow">You are not logged in.</Text>
				<Box marginTop={1}>
					<Text dimColor>Run </Text>
					<Text color="cyan">wosh auth signup</Text>
					<Text dimColor> to create an account</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'error') {
		return (
			<Box flexDirection="column" marginTop={1}>
				<Text color="red">Something went wrong</Text>
				<Box paddingLeft={2} marginTop={1}>
					<Text color="red">[error] : {error}</Text>
				</Box>
			</Box>
		);
	}

	if (step === 'success' && profile) {
		return (
			<Box flexDirection="column" marginTop={1}>
				<Text color="cyan">{profile.name}</Text>
				<Text color="gray">{profile.email}</Text>
			</Box>
		);
	}

	return null;
};
