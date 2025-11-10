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
npm install -g wosh-cli
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

## Configuration

Wosh CLI requires the following environment variables to be configured:

- `BACKEND_BASE_URL` - The URL of your Wosh backend server
- `DEVICE_STORAGE_SALT` - Salt for local encryption
- `CLI_TOKEN_HASH` - Hash for CLI token validation
- `KEYS_ENCRYPTION_SALT` - Salt for key encryption

These can be set in a `.env` file in your project root or as system environment variables.

## Security

- All secrets are encrypted end-to-end
- Private keys never leave your device
- CLI tokens can be revoked at any time
- Session-based authentication with secure token storage

## How It Works

1. **Authentication**: Login with your credentials or CLI token
2. **Key Exchange**: Your device generates encryption keys locally
3. **Secret Fetching**: Encrypted secrets are fetched from the server
4. **Decryption**: Secrets are decrypted locally on your device
5. **Injection**: Decrypted secrets are injected as environment variables
6. **Execution**: Your command runs with access to secrets

## Project Structure

Wosh CLI supports organizations and projects:

```
Organization
├── Project A
│   ├── Secret 1
│   ├── Secret 2
│   └── Secret 3
└── Project B
    ├── Secret 1
    └── Secret 2
```

## Troubleshooting

### Command not found

If you get "wosh: command not found", ensure npm global bin is in your PATH:

```bash
npm config get prefix
```

Add the bin directory to your PATH in `.bashrc`, `.zshrc`, or equivalent:

```bash
export PATH="$PATH:$(npm config get prefix)/bin"
```

### Authentication issues

If you're having trouble authenticating:

```bash
# Logout and login again
wosh auth logout
wosh auth login

# Check your current authentication status
wosh auth whoami
```

### Secrets not loading

Ensure you're in the correct project context and have the necessary permissions.

## Development

### Building from source

```bash
# Clone the repository
git clone https://github.com/yourusername/wosh-cli.git
cd wosh-cli

# Install dependencies
npm install

# Build the project
npm run build

# Link locally for testing
npm link
```

### Running tests

```bash
npm test
```

## Requirements

- Node.js >= 16
- npm or yarn

## License

MIT

## Support

For issues, questions, or contributions, please visit our GitHub repository or contact support.

## Roadmap

- Organization management commands
- Project management commands
- Secret management (create, update, delete)
- Team collaboration features
- Audit logs
- Secret versioning
- Import/export functionality
