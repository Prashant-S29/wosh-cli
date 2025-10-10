import {Box, Text} from 'ink';

export default function App() {
	const progress = 70;
	const barLength = 20;
	const filledLength = Math.round((barLength * progress) / 100);
	const emptyLength = barLength - filledLength;
	const progressBar = '█'.repeat(filledLength) + '░'.repeat(emptyLength);

	return (
		<Box flexDirection="column" padding={1}>
			<Box marginBottom={1}>
				<Text color="gray">Welcome to WoshVault!</Text>
			</Box>

			<Box marginBottom={1}>
				<Text>Progress: </Text>
				<Text bold color="green">
					{progress}%
				</Text>
			</Box>

			<Box>
				<Text color="cyan">{progressBar}</Text>
			</Box>
		</Box>
	);
}
