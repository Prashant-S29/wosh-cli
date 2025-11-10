import {Box, Text} from 'ink';
import {Header} from './components/header.js';

export default function App() {
	return (
		<Box flexDirection="column" padding={1}>
			<Header />
			<Box marginTop={1}>
				<Text color="gray">Welcome to Wosh. We are cooking!</Text>
			</Box>
		</Box>
	);
}
