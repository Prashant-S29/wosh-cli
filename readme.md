# Wosh CLI

A CLI tool for interacting with Wosh - A local first secret management tool.

## Features

- Secure secret management with end-to-end encryption
- Run commands with automatically injected secrets
- Watch mode to monitor which secrets are being used
- CLI token authentication for CI/CD pipelines
- Multi-organization and project support

## Installation

```bash
npm install -g wosh
```

## Quick Start

### 1. Authentication

Create an account or login:

```bash
# Sign up for a new account
wosh auth signup

# Or login to existing account
wosh auth login

# Check your authentication status
wosh auth whoami
```

### 2. Run commands with secrets

```bash
# Display all secrets (without exposing values)
wosh run

# Run a command with secrets injected as environment variables
wosh run --command="npm run dev"

# Run with watch mode to see which secrets are being used
wosh run --command="npm start" --watch
```

## Commands

### Authentication

| Command            | Description                      |
| ------------------ | -------------------------------- |
| `wosh auth signup` | Create a new account             |
| `wosh auth login`  | Login to your account            |
| `wosh auth logout` | Logout from your account         |
| `wosh auth whoami` | Display current user information |

### CLI Token Management

CLI tokens are useful for CI/CD pipelines and automated workflows.

| Command                         | Description                           |
| ------------------------------- | ------------------------------------- |
| `wosh auth cli --token=<token>` | Set up CLI token for authentication   |
| `wosh auth cli info`            | Display current CLI token information |
| `wosh auth cli revoke`          | Revoke the current CLI token          |

### Running Commands with Secrets

| Command                              | Description                          |
| ------------------------------------ | ------------------------------------ |
| `wosh run`                           | Fetch and display available secrets  |
| `wosh run --command="<cmd>"`         | Run command with secrets injected    |
| `wosh run --command="<cmd>" --watch` | Run command and monitor secret usage |

## Usage Examples

### Development workflow

```bash
# Start your development server with secrets
wosh run --command="npm run dev"

# Run tests with secrets
wosh run --command="npm test"

# Build your project with secrets
wosh run --command="npm run build"
```

### CI/CD Integration

```bash
# Set CLI token (in your CI/CD environment)
wosh auth cli --token=$WOSH_CLI_TOKEN

# Run deployment with secrets
wosh run --command="./deploy.sh"
```

### Multiple commands

```bash
# Chain multiple commands
wosh run --command="npm install && npm run build && npm start"
```

### Watch mode

Monitor which environment variables your application is accessing:

```bash
wosh run --command="node app.js" --watch
```