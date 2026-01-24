# Taildrop Web

A web application for sending files to devices on your Tailscale network via drag-and-drop. Built with Go and deployed to Fly.io.

## Features

- **GitHub OAuth Authentication**: Secure login using GitHub accounts
- **Drag & Drop Upload**: Simple, intuitive file transfer interface
- **Device Discovery**: Automatically lists all devices on your tailnet
- **Secure File Transfer**: Uses Tailscale's built-in file copy functionality
- **OAuth API Access**: Uses Tailscale OAuth client credentials for API calls
- **Responsive Design**: Works on desktop and mobile devices

## Prerequisites

- A [Tailscale](https://tailscale.com/) account and tailnet
- A [GitHub](https://github.com/) account
- [Fly.io](https://fly.io/) account (free tier available)
- [flyctl](https://fly.io/docs/hands-on/install-flyctl/) CLI installed
- Go 1.22+ (for local development)

## Setup

### 1. Tailscale OAuth Client

1. Go to the [Tailscale Admin Console](https://login.tailscale.com/admin/settings/trust-credentials)
2. Click **"+ Credential"**
3. Set the following:
   - **Name**: `taildrop.me`
   - **Read**: Check `devices`
   - **Write**: (none needed)
4. Click **"Generate credential"**
5. **IMPORTANT**: Copy both the **Client ID** and **Client Secret** immediately - you won't be able to see the secret again!

### 2. Tailscale Auth Key

1. Go to [Tailscale Auth Keys](https://login.tailscale.com/admin/settings/keys)
2. Click **"Generate auth key"**
3. Set the following:
   - **Description**: `Taildrop Web Fly.io`
   - **Reusable**: ✓ (checked)
   - **Ephemeral**: ✓ (checked, recommended for Fly.io deployments)
   - **Expiration**: Choose appropriate duration
4. Save the generated auth key (you'll need this as `TAILSCALE_AUTH_KEY`)

### 3. GitHub OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click **"New OAuth App"**
3. Fill in the details:
   - **Application name**: `Taildrop Web`
   - **Homepage URL**: `https://taildrop.me` (or your actual URL)
   - **Authorization callback URL**: `https://taildrop.me/auth/callback` (or your actual URL + `/auth/callback`)
     - For local development: `http://localhost:8080/auth/callback`
4. Click **"Register application"**
5. On the app page, click **"Generate a new client secret"**
6. Save both the **Client ID** and **Client Secret** (you'll need these as `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`)

### 4. Configure Authorized Users

**IMPORTANT**: By default, if you don't set `ALLOWED_GITHUB_USERS`, **any GitHub user** can access your app. You should configure a whitelist of allowed users.

Create a comma-separated list of GitHub usernames that should have access:
```
ALLOWED_GITHUB_USERS="username1,username2,username3"
```

For example:
```
ALLOWED_GITHUB_USERS="peterwald,alice,bob"
```

When a user tries to log in:
- If their GitHub username is in the list, they're granted access
- If not, they see an "Access denied" message
- Usernames are case-insensitive

### 5. Get Your Tailnet Name

Your tailnet name is typically your email address (for personal accounts) or your organization domain. You can find it in the Tailscale admin console URL or on your [Tailscale Settings page](https://login.tailscale.com/admin/settings/general).

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
  TAILSCALE_CLIENT_ID="your_tailscale_client_id" \
  TAILSCALE_CLIENT_SECRET="your_tailscale_client_secret" \
  TAILSCALE_AUTH_KEY="your_tailscale_auth_key" \
  TAILNET_NAME="your@email.com" \
  GITHUB_CLIENT_ID="your_github_client_id" \
  GITHUB_CLIENT_SECRET="your_github_client_secret" \
  ALLOWED_GITHUB_USERS="username1,username2,username3" \
  APP_URL="https://taildrop-me.fly.dev"
```

**Important**:
- Update `APP_URL` to match your actual Fly.io app URL or custom domain
- Replace `username1,username2,username3` with actual GitHub usernames that should have access

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

### 7. Update GitHub OAuth Callback URL

After deploying, if your app URL changed, update the GitHub OAuth app:
1. Go to your [GitHub OAuth App settings](https://github.com/settings/developers)
2. Update the **Authorization callback URL** to match your deployed app (e.g., `https://taildrop-me.fly.dev/auth/callback`)

### 8. Open the Application

```bash
flyctl open
```

Or access it via your custom domain (see below for custom domain setup).

## Environment Variables

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `TAILSCALE_CLIENT_ID` | OAuth client ID from Tailscale | Yes | `k123abc...` |
| `TAILSCALE_CLIENT_SECRET` | OAuth client secret from Tailscale | Yes | `tskey-client-k123abc...` |
| `TAILSCALE_AUTH_KEY` | Auth key for Fly.io to join tailnet | Yes | `tskey-auth-k123abc...` |
| `TAILNET_NAME` | Your tailnet name (email or org domain) | Yes | `user@example.com` |
| `GITHUB_CLIENT_ID` | GitHub OAuth app client ID | Yes | `Iv1.abc123...` |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth app client secret | Yes | `ghp_abc123...` |
| `ALLOWED_GITHUB_USERS` | Comma-separated list of GitHub usernames | **Recommended** | `user1,user2,user3` |
| `APP_URL` | Full URL where app is hosted | Yes | `https://taildrop-me.fly.dev` |
| `PORT` | Server port | No (default: 8080) | `8080` |

**Note**: If `ALLOWED_GITHUB_USERS` is not set, any GitHub user can access the app (not recommended for production).

## Custom Domain Setup

To use a custom domain with your Fly.io app:

```bash
# Add your domain
flyctl certs add taildrop.yourdomain.com

# Add DNS CNAME record pointing to your-app.fly.dev
# Type: CNAME, Name: taildrop, Value: taildrop-me.fly.dev
```

After setting up the custom domain:
1. Update `APP_URL` environment variable: `flyctl secrets set APP_URL="https://taildrop.yourdomain.com"`
2. Update GitHub OAuth callback URL to `https://taildrop.yourdomain.com/auth/callback`

Fly.io will automatically provision and renew SSL certificates.

## Local Development

### 1. Install Dependencies

```bash
go mod download
```

### 2. Set Environment Variables

Create a `.env` file (not tracked by git):

```bash
export TAILSCALE_CLIENT_ID="your_tailscale_client_id"
export TAILSCALE_CLIENT_SECRET="your_tailscale_client_secret"
export TAILNET_NAME="your@email.com"
export GITHUB_CLIENT_ID="your_github_client_id"
export GITHUB_CLIENT_SECRET="your_github_client_secret"
export ALLOWED_GITHUB_USERS="your_github_username"
export APP_URL="http://localhost:8080"
export PORT="8080"
```

Load the environment variables:

```bash
source .env
```

### 3. Configure GitHub OAuth for Local Development

In your GitHub OAuth app settings, add a second authorization callback URL:
- `http://localhost:8080/auth/callback`

This allows you to test locally while keeping the production callback URL.

### 4. Ensure Tailscale is Running

Make sure Tailscale is installed and running on your local machine:

```bash
tailscale status
```

### 5. Run the Application

```bash
go run main.go
```

Visit `http://localhost:8080` in your browser and sign in with GitHub.

## Usage

1. **Sign In**: Click "Sign in with GitHub" to authenticate
2. **Select Device**: Choose a target device from the dropdown menu
3. **Upload File**: Drag and drop a file onto the upload zone (or click to browse)
4. **Send**: Click "Send File" to transfer the file to the selected device

The recipient device will receive a notification about the incoming file, which they can accept through their Tailscale client.

## Architecture

- **Backend**: Go web server with dual OAuth flows
  - GitHub OAuth (authorization code flow) for user authentication
  - Tailscale OAuth (client credentials flow) for API access
- **Frontend**: Single-page HTML with embedded CSS and JavaScript
- **File Transfer**: Uses `tailscale file cp` command on the server
- **Deployment**: Docker container on Fly.io with Tailscale sidecar
- **Security**: Session-based authentication, device name sanitization, HTTPS enforcement

## Security Features

- **GitHub OAuth Authentication**: Users must sign in with GitHub to access the app
- **User Authorization**: Whitelist of allowed GitHub usernames (via `ALLOWED_GITHUB_USERS`)
- **Session Management**: Secure HTTP-only cookies with 24-hour expiration
- **HTTPS Enforcement**: All production traffic encrypted via Fly.io
- **Input Validation**: Device names sanitized to prevent command injection
- **Audit Logging**: File transfers logged with username and timestamp
- **Tailscale Network**: File transfers use encrypted Tailscale connections

## Troubleshooting

### "Failed to load devices"

- Verify `TAILSCALE_CLIENT_ID` and `TAILSCALE_CLIENT_SECRET` are correct
- Check that the OAuth client has `devices:read` scope
- Ensure `TAILNET_NAME` matches your tailnet exactly
- Check logs: `flyctl logs`

### "Failed to send file"

- Verify the Fly.io instance is connected to your tailnet: `flyctl ssh console -C "tailscale status"`
- Check that the target device is online and accepting files
- Review logs: `flyctl logs`

### GitHub OAuth fails

- Verify the callback URL in GitHub matches your `APP_URL` + `/auth/callback`
- Check that `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` are correct
- Ensure cookies are enabled in your browser
- For local development, make sure you added `http://localhost:8080/auth/callback` to GitHub

### Tailscale not connecting on Fly.io

- Verify `TAILSCALE_AUTH_KEY` is correct and not expired
- Check that the auth key is set as reusable
- View startup logs: `flyctl logs`
- SSH into the instance: `flyctl ssh console -C "tailscale status"`

### "Missing state cookie" or "Invalid state parameter"

- This is a CSRF protection. Clear your browser cookies and try again
- Ensure your `APP_URL` is set correctly (should match the actual URL you're accessing)
- Check that cookies are enabled in your browser

### "Access denied" after GitHub login

- Your GitHub username is not in the `ALLOWED_GITHUB_USERS` list
- Check the server logs to see which username tried to log in: `flyctl logs`
- Add your GitHub username to the allowed users list: `flyctl secrets set ALLOWED_GITHUB_USERS="existing,newuser"`
- Make sure usernames are spelled correctly (case-insensitive but must match)
- If `ALLOWED_GITHUB_USERS` is not set at all, check the logs for a warning message

## Project Structure

```
├── main.go              # Go web server with dual OAuth flows
├── templates/
│   └── index.html       # UI with GitHub login and drag-drop zone
├── go.mod               # Go module definition
├── Dockerfile           # Multi-stage build with Tailscale
├── start.sh             # Startup script for Tailscale + app
├── fly.toml             # Fly.io configuration
├── .gitignore           # Git ignore rules
└── README.md            # This file
```

## How It Works

1. **User Authentication**: Users sign in with GitHub OAuth to prove their identity
2. **Session Creation**: App creates a secure session cookie upon successful GitHub login
3. **API Access**: App uses Tailscale OAuth client credentials to fetch device list
4. **File Upload**: Authenticated users can upload files and select target devices
5. **File Transfer**: App executes `tailscale file cp` to send files over encrypted Tailscale network
6. **Audit Trail**: All file transfers are logged with username and timestamp

## References

- [GitHub OAuth Apps Documentation](https://docs.github.com/en/apps/oauth-apps)
- [Tailscale OAuth Clients Documentation](https://tailscale.com/kb/1215/oauth-clients)
- [Tailscale API Documentation](https://tailscale.com/kb/1101/api)
- [Fly.io Documentation](https://fly.io/docs/)

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
