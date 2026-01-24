# Taildrop Web

A web application for sending files to devices on your Tailscale network via drag-and-drop. Built with Go and deployed to Fly.io.

## Features

- **Tailscale OAuth Authentication**: Secure login using your Tailscale account
- **Device Discovery**: Automatically lists all devices on your tailnet
- **Drag & Drop Upload**: Simple, intuitive file transfer interface
- **Secure File Transfer**: Uses Tailscale's built-in file copy functionality
- **Responsive Design**: Works on desktop and mobile devices

## Prerequisites

- A [Tailscale](https://tailscale.com/) account and tailnet
- [Fly.io](https://fly.io/) account (free tier available)
- [flyctl](https://fly.io/docs/hands-on/install-flyctl/) CLI installed
- Go 1.22+ (for local development)

## Tailscale Setup

### 1. Create OAuth Client

1. Go to the [Tailscale Admin Console](https://login.tailscale.com/admin/settings/trust-credentials)
2. Click **"+ Credential"**
3. Set the following:
   - **Name**: `taildrop.me`
   - **Scopes**: Select `devices:read`
   - **Redirect URLs**: Add your callback URL (e.g., `https://your-app.fly.dev/callback`)
     - For local development, also add: `http://localhost:8080/callback`
4. Click **"Generate credential"**
5. Save the **Client ID** and **Client Secret** (you'll need these as environment variables)

### 2. Create API Key

1. Go to [Tailscale Keys](https://login.tailscale.com/admin/settings/keys)
2. Click **"Generate API access token"**
3. Set the following:
   - **Description**: `Taildrop Web API`
   - **Expiration**: Choose appropriate duration
4. Save the generated API key (you'll need this as `TAILSCALE_API_KEY`)

### 3. Create Auth Key

1. Go to [Tailscale Auth Keys](https://login.tailscale.com/admin/settings/keys)
2. Click **"Generate auth key"**
3. Set the following:
   - **Description**: `Taildrop Web Fly.io`
   - **Reusable**: ✓ (checked)
   - **Ephemeral**: ✓ (checked, recommended for Fly.io deployments)
   - **Expiration**: Choose appropriate duration
4. Save the generated auth key (you'll need this as `TAILSCALE_AUTH_KEY`)

### 4. Get Your Tailnet Name

Your tailnet name is typically your email address (for personal accounts) or your organization domain. You can find it in the Tailscale admin console URL:
- `https://login.tailscale.com/admin/machines/`

## Fly.io Deployment

### 1. Install and Login

```bash
# Install flyctl (if not already installed)
curl -L https://fly.io/install.sh | sh

# Login to Fly.io
flyctl auth login
```

### 2. Create Fly.io App

```bash
# Create a new app (replace 'taildrop-me' with your preferred name)
flyctl apps create taildrop-me

# Allocate an IPv4 address (optional but recommended)
flyctl ips allocate-v4
```

### 3. Set Environment Variables

```bash
# Set all required secrets
flyctl secrets set \
  TAILSCALE_CLIENT_ID="your_oauth_client_id" \
  TAILSCALE_CLIENT_SECRET="your_oauth_client_secret" \
  TAILSCALE_API_KEY="your_api_key" \
  TAILSCALE_AUTH_KEY="your_auth_key" \
  TAILNET_NAME="your@email.com" \
  REDIRECT_URL="https://your-app.fly.dev/callback"
```

### 4. Update fly.toml

Edit [fly.toml](fly.toml) and update:
- `app = "taildrop-me"` to match your app name
- `primary_region = "iad"` to your preferred region (see [Fly.io regions](https://fly.io/docs/reference/regions/))

### 5. Create Volume for Tailscale State

```bash
# Create a persistent volume for Tailscale state
flyctl volumes create tailscale_data --size 1
```

### 6. Deploy

```bash
# Deploy the application
flyctl deploy

# Check the status
flyctl status

# View logs
flyctl logs
```

### 7. Open the Application

```bash
flyctl open
```

## Environment Variables

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `TAILSCALE_CLIENT_ID` | OAuth client ID from Tailscale | Yes | `k123abc...` |
| `TAILSCALE_CLIENT_SECRET` | OAuth client secret from Tailscale | Yes | `tskey-client-k123abc...` |
| `TAILSCALE_API_KEY` | API key for fetching device list | Yes | `tskey-api-k123abc...` |
| `TAILSCALE_AUTH_KEY` | Auth key for Fly.io to join tailnet | Yes | `tskey-auth-k123abc...` |
| `TAILNET_NAME` | Your tailnet name (email or org domain) | Yes | `user@example.com` |
| `REDIRECT_URL` | OAuth callback URL | Yes | `https://your-app.fly.dev/callback` |
| `PORT` | Server port | No (default: 8080) | `8080` |

## Local Development

### 1. Install Dependencies

```bash
go mod download
```

### 2. Set Environment Variables

Create a `.env` file (not tracked by git):

```bash
export TAILSCALE_CLIENT_ID="your_oauth_client_id"
export TAILSCALE_CLIENT_SECRET="your_oauth_client_secret"
export TAILSCALE_API_KEY="your_api_key"
export TAILNET_NAME="your@email.com"
export REDIRECT_URL="http://localhost:8080/callback"
export PORT="8080"
```

Load the environment variables:

```bash
source .env
```

### 3. Ensure Tailscale is Running

Make sure Tailscale is installed and running on your local machine:

```bash
tailscale status
```

### 4. Run the Application

```bash
go run main.go
```

Visit `http://localhost:8080` in your browser.

## Usage

1. **Login**: Click "Login with Tailscale" and authorize the application
2. **Select Device**: Choose a target device from the dropdown menu
3. **Upload File**: Drag and drop a file onto the upload zone (or click to browse)
4. **Send**: Click "Send File" to transfer the file to the selected device

The recipient device will receive a notification about the incoming file, which they can accept through their Tailscale client.

## Architecture

- **Backend**: Go web server with OAuth2 authentication
- **Frontend**: Single-page HTML with embedded CSS and JavaScript
- **Authentication**: Tailscale OAuth with in-memory session management
- **File Transfer**: Uses `tailscale file cp` command on the server
- **Deployment**: Docker container on Fly.io with Tailscale sidecar

## Security Features

- HTTP-only secure cookies for session management
- HTTPS enforcement via Fly.io configuration
- Device name sanitization to prevent command injection
- OAuth state parameter validation
- API key authentication for Tailscale API calls

## Troubleshooting

### "Failed to load devices"

- Verify `TAILSCALE_API_KEY` is correct
- Check that the API key has not expired
- Ensure `TAILNET_NAME` matches your tailnet

### "Failed to send file"

- Verify the Fly.io instance is connected to your tailnet: `flyctl ssh console -C "tailscale status"`
- Check that the target device is online and accepting files
- Review logs: `flyctl logs`

### OAuth callback fails

- Verify `REDIRECT_URL` matches the URL configured in Tailscale OAuth settings
- Ensure the URL is accessible (use `https://` for production)
- Check that `TAILSCALE_CLIENT_ID` and `TAILSCALE_CLIENT_SECRET` are correct

### Tailscale not connecting on Fly.io

- Verify `TAILSCALE_AUTH_KEY` is correct and not expired
- Check that the auth key is set as reusable
- View startup logs: `flyctl logs`
- SSH into the instance and check Tailscale status: `flyctl ssh console -C "tailscale status"`

## Project Structure

```
├── main.go              # Go web server with OAuth, sessions, endpoints
├── templates/
│   └── index.html       # UI with login, device selector, drag-drop zone
├── go.mod               # Go module definition
├── Dockerfile           # Multi-stage build with Tailscale
├── start.sh             # Startup script for Tailscale + app
├── fly.toml             # Fly.io configuration
├── .gitignore           # Git ignore rules
└── README.md            # This file
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
