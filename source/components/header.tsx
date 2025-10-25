import chalk from 'chalk';
import figlet from 'figlet';
import {Text} from 'ink';
import React from 'react';

export const Header: React.FC = () => {
	const bannerText = figlet.textSync('WoshVault', {
		font: 'Slant',
		horizontalLayout: 'default',
		verticalLayout: 'default',
	});

	const lines = bannerText.split('\n').filter(l => l.trim());

	const gradientColors = [
		chalk.rgb(100, 200, 255),
		chalk.rgb(120, 180, 255),
		chalk.rgb(150, 150, 255),
		chalk.rgb(200, 100, 200),
		chalk.rgb(220, 100, 180),
	] as const;

	const gradientBody = lines.map((line, idx) => {
		const colorIdx = Math.min(idx, gradientColors.length - 1);
		const colorFn = gradientColors[colorIdx];
		return colorFn ? colorFn(line) : line;
	});

	return <Text>{gradientBody.join('\n')}</Text>;
};
