#!/usr/bin/env node

import {render} from 'ink';
import meow from 'meow';

// components
import App from './app.js';
import {Signup} from './auth/signup.js';
import {Whoami} from './auth/whoami.js';


const cli = meow(
	`
	Usage
	  $ wosh <command> <subcommand>

	Commands

	auth
	  $ wosh auth login        login into your account
	  $ wosh auth signup       create new account
	  $ wosh auth logout       logout
	  $ wosh auth whoami       show profile info

	organization
	  (coming soon)

	project
	  (coming soon)

	secret
	  (coming soon)
	`,
	{
		importMeta: import.meta,
		flags: {},
	},
);

const [command, subcommand] = cli.input;

// route commands
if (command === 'auth' && subcommand === 'signup') {
	render(<Signup />);
} else if (command === 'auth' && subcommand === 'whoami') {
	render(<Whoami />);
} else if (command === 'auth' && subcommand === 'login') {
	// TODO: implement login
	console.log('Login coming soon!');
} else if (command === 'auth' && subcommand === 'logout') {
	// TODO: implement logout
	console.log('Logout coming soon!');
} else {
	render(<App />);
}
