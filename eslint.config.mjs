import js from '@eslint/js';
import react from 'eslint-plugin-react';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';
import prettierConfig from 'eslint-config-prettier';

export default [
	// Ignore patterns
	{
		ignores: ['dist/**', 'build/**', 'node_modules/**', 'coverage/**'],
	},

	// Base JavaScript config
	js.configs.recommended,

	// Main configuration for JS files
	{
		files: ['**/*.js', '**/*.jsx', '**/*.mjs'],
		languageOptions: {
			ecmaVersion: 'latest',
			sourceType: 'module',
			globals: {
				...globals.node,
				...globals.es2021,
				fetch: 'readonly',
				FormData: 'readonly',
				Headers: 'readonly',
				Request: 'readonly',
				Response: 'readonly',
			},
			parserOptions: {
				ecmaFeatures: {
					jsx: true,
				},
			},
		},
		plugins: {
			react,
			'react-hooks': reactHooks,
		},
		settings: {
			react: {
				version: 'detect',
			},
		},
		rules: {
			// React rules
			'react/react-in-jsx-scope': 'off',
			'react/prop-types': 'off',
			'react/jsx-uses-react': 'off',
			'react/jsx-uses-vars': 'error',
			'react/jsx-no-undef': 'error',
			'react/jsx-key': 'error',
			'react/no-unknown-property': 'error',

			// React Hooks rules
			'react-hooks/rules-of-hooks': 'error',
			'react-hooks/exhaustive-deps': 'warn',

			// General best practices
			'no-console': 'off',
			'no-unused-vars': [
				'warn',
				{
					argsIgnorePattern: '^_',
					varsIgnorePattern: '^_',
					caughtErrorsIgnorePattern: '^_',
				},
			],
			'prefer-const': 'error',
			'no-var': 'error',
			'object-shorthand': 'warn',
			'quote-props': ['warn', 'as-needed'],

			// Code quality
			eqeqeq: ['error', 'always', {null: 'ignore'}],
			'no-throw-literal': 'error',
			'prefer-promise-reject-errors': 'error',
			'no-return-await': 'error',

			// Style preferences
			quotes: ['warn', 'single', {avoidEscape: true}],
			semi: ['warn', 'always'],
			'comma-dangle': ['warn', 'always-multiline'],
			indent: ['warn', 'tab', {SwitchCase: 1}],
			'no-tabs': 'off',

			// Import/require
			'no-duplicate-imports': 'error',

			// Async/await
			'require-await': 'warn',
			'no-async-promise-executor': 'error',
		},
	},

	// TypeScript files
	{
		files: ['**/*.ts', '**/*.tsx'],
		languageOptions: {
			ecmaVersion: 'latest',
			sourceType: 'module',
			parser: await import('@typescript-eslint/parser').then(m => m.default),
			parserOptions: {
				project: './tsconfig.json',
				ecmaFeatures: {
					jsx: true,
				},
			},
			globals: {
				...globals.node,
				...globals.es2021,
				fetch: 'readonly',
				FormData: 'readonly',
				Headers: 'readonly',
				Request: 'readonly',
				Response: 'readonly',
			},
		},
		plugins: {
			react,
			'react-hooks': reactHooks,
			'@typescript-eslint': await import(
				'@typescript-eslint/eslint-plugin'
			).then(m => m.default),
		},
		settings: {
			react: {
				version: 'detect',
			},
		},
		rules: {
			// Disable base rules that are covered by TypeScript equivalents
			'no-unused-vars': 'off',

			// React rules
			'react/react-in-jsx-scope': 'off',
			'react/prop-types': 'off',
			'react/jsx-uses-react': 'off',
			'react/jsx-uses-vars': 'error',
			'react/jsx-no-undef': 'error',
			'react/jsx-key': 'error',
			'react/no-unknown-property': 'error',

			// React Hooks rules
			'react-hooks/rules-of-hooks': 'error',
			'react-hooks/exhaustive-deps': 'warn',

			// TypeScript specific rules
			'@typescript-eslint/no-unused-vars': [
				'warn',
				{
					argsIgnorePattern: '^_',
					varsIgnorePattern: '^_',
				},
			],
			'@typescript-eslint/no-explicit-any': 'warn',
			'@typescript-eslint/explicit-module-boundary-types': 'off',
			'@typescript-eslint/no-non-null-assertion': 'warn',
		},
	},
	...prettierConfig,
];
