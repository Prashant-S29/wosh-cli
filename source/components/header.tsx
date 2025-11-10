import chalk from 'chalk';
import figlet from 'figlet';
import {Text} from 'ink';
import React from 'react';

export const Header: React.FC = () => {
	const bannerText = figlet.textSync('Wosh', {
		font: 'Slant',
		horizontalLayout: 'default',
		verticalLayout: 'default',
	});

	const lines = bannerText.split('\n').filter(l => l.trim());

	const gradientBody = lines.map(line => {
		const colorFn = chalk.white;
		return colorFn ? colorFn(line) : line;
	});

	return <Text>{gradientBody.join('\n')}</Text>;
};
