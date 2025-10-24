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

const cli = meow(
	`
	Usage
	  $ wosh <command> <subcommand> [action]

	Commands

	auth
	  $ wosh auth login                login into your account
	  $ wosh auth signup               create new account
	  $ wosh auth logout               logout
	  $ wosh auth whoami               show profile info
	  $ wosh auth cli --token=<token>    setup CLI token
	  $ wosh auth cli info             show CLI token information
	  $ wosh auth cli revoke           revoke CLI token

	organization
	  (coming soon)

	project
	  (coming soon)

	secret
	  (coming soon)
	`,
	{
		importMeta: import.meta,
		flags: {
			token: {
				type: 'string',
				isRequired: false,
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
	} else {
		return <App />;
	}
};

render(
	<Provider>
		<Router />
	</Provider>,
);
