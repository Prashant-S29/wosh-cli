#!/usr/bin/env node

import 'dotenv/config';
import {render} from 'ink';
import meow from 'meow';
import React from 'react';

// components
import App from './app.js';
import {Signup} from './auth/signup.js';
import {Whoami} from './auth/whoami.js';
import {Provider} from './components/common/Provider/Provider.js';
import {Logout} from './auth/logout.js';
import {CLIToken} from './auth/cliToken.js';
import {CLITokenInfo} from './auth/cliTokenInfo.js';
import {Run} from './run/run.js';

const cli = meow(
	`
	Usage
	  $ wosh <command> <subcommand> [action]

	Commands

	auth
	  $ wosh auth login                      login into your account
	  $ wosh auth signup                     create new account
	  $ wosh auth logout                     logout
	  $ wosh auth whoami                     show profile info
	  $ wosh auth cli --token=<token>        setup CLI token
	  $ wosh auth cli info                   show CLI token information
	  $ wosh auth cli revoke                 revoke CLI token

	run
	  $ wosh run                             fetch and decrypt secrets (display only)
	  $ wosh run --command="npm run dev"     run command with injected secrets
	  $ wosh run --command="npm run dev" --watch     run command and show secret keys being used

	organization
	  (coming soon)

	project
	  (coming soon)

	secret
	  (coming soon)

	Examples
	  $ wosh run                                     # Display all secrets
	  $ wosh run --command="npm run dev"     # Run dev server with secrets
	  $ wosh run --command="npm run dev" --watch     # Run and show which secrets are used
	  $ wosh run --command="node app.js"     # Run Node.js app with secrets
	  $ wosh run --command="build && test"   # Run multiple commands
	`,
	{
		importMeta: import.meta,
		flags: {
			token: {
				type: 'string',
				isRequired: false,
			},
			command: {
				type: 'string',
				isRequired: false,
			},
			watch: {
				type: 'boolean',
				isRequired: false,
				default: false,
			},
		},
	},
);

const [command, subcommand, action] = cli.input;

// Router component to handle command routing
const Router: React.FC = () => {
	if (command === 'auth' && subcommand === 'signup') {
		return <Signup mode="signup" />;
	} else if (command === 'auth' && subcommand === 'whoami') {
		return <Whoami />;
	} else if (command === 'auth' && subcommand === 'login') {
		return <Signup mode="login" />;
	} else if (command === 'auth' && subcommand === 'logout') {
		return <Logout />;
	} else if (command === 'auth' && subcommand === 'cli') {
		if (action === 'revoke') {
			return <CLIToken mode="revoke" />;
		} else if (action === 'info') {
			return <CLITokenInfo />;
		} else {
			// Get token from flags
			const token = cli.flags.token;
			return <CLIToken mode="set" token={token} />;
		}
	} else if (command === 'run') {
		// Pass command flag and watch flag to Run component
		const commandToRun = cli.flags.command;
		const watch = cli.flags.watch;
		return <Run command={commandToRun} watch={watch} />;
	} else {
		return <App />;
	}
};

render(
	<Provider>
		<Router />
	</Provider>,
);
