# Taildrop Web

A web application for sending files to devices on your Tailscale network via drag-and-drop. Built with Go and deployed to Fly.io.

## Features

- **Drag & Drop Upload**: Simple, intuitive file transfer interface
- **Device Discovery**: Automatically lists all devices on your tailnet
- **Secure File Transfer**: Uses Tailscale's built-in file copy functionality
- **OAuth API Access**: Uses Tailscale OAuth client credentials for API calls
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
   - **Read**: Check `devices`
   - **Write**: (none needed)
4. Click **"Generate credential"**
5. **IMPORTANT**: Copy both the **Client ID** and **Client Secret** immediately - you won't be able to see the secret again!

### 2. Create Auth Key

1. Go to [Tailscale Auth Keys](https://login.tailscale.com/admin/settings/keys)
2. Click **"Generate auth key"**
3. Set the following:
   - **Description**: `Taildrop Web Fly.io`
   - **Reusable**: ✓ (checked)
   - **Ephemeral**: ✓ (checked, recommended for Fly.io deployments)
   - **Expiration**: Choose appropriate duration
4. Save the generated auth key (you'll need this as `TAILSCALE_AUTH_KEY`)

### 3. Get Your Tailnet Name

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
  TAILSCALE_CLIENT_ID="your_oauth_client_id" \
  TAILSCALE_CLIENT_SECRET="your_oauth_client_secret" \
  TAILSCALE_AUTH_KEY="your_auth_key" \
  TAILNET_NAME="your@email.com"
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

Or access it via your custom domain (see below for custom domain setup).

## Environment Variables

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `TAILSCALE_CLIENT_ID` | OAuth client ID from Tailscale | Yes | `k123abc...` |
| `TAILSCALE_CLIENT_SECRET` | OAuth client secret from Tailscale | Yes | `tskey-client-k123abc...` |
| `TAILSCALE_AUTH_KEY` | Auth key for Fly.io to join tailnet | Yes | `tskey-auth-k123abc...` |
| `TAILNET_NAME` | Your tailnet name (email or org domain) | Yes | `user@example.com` |
| `PORT` | Server port | No (default: 8080) | `8080` |

**Note**: The previous version used `TAILSCALE_API_KEY` and `REDIRECT_URL` - these are no longer needed with the OAuth client credentials flow.

## Custom Domain Setup

To use a custom domain with your Fly.io app:

```bash
# Add your domain
flyctl certs add taildrop.yourdomain.com

# Add DNS CNAME record pointing to your-app.fly.dev
# Type: CNAME, Name: taildrop, Value: taildrop-me.fly.dev
```

Fly.io will automatically provision and renew SSL certificates.

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
export TAILNET_NAME="your@email.com"
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

1. **Select Device**: Choose a target device from the dropdown menu
2. **Upload File**: Drag and drop a file onto the upload zone (or click to browse)
3. **Send**: Click "Send File" to transfer the file to the selected device

The recipient device will receive a notification about the incoming file, which they can accept through their Tailscale client.

## Architecture

- **Backend**: Go web server with OAuth2 client credentials flow
- **Frontend**: Single-page HTML with embedded CSS and JavaScript
- **API Access**: Tailscale OAuth client credentials for device list
- **File Transfer**: Uses `tailscale file cp` command on the server
- **Deployment**: Docker container on Fly.io with Tailscale sidecar
- **Security**: Device name sanitization, HTTPS enforcement

## Key Changes from Traditional OAuth

This app uses **OAuth 2.0 Client Credentials Flow** instead of the authorization code flow:

- **No user login required** - The app uses its own credentials to access the Tailscale API
- **Simpler setup** - No redirect URLs or callback handling
- **Network-based access** - Anyone who can reach the app on your network can use it
- **Automatic token refresh** - The OAuth client handles token expiration automatically

This is appropriate because:
1. The app runs on your Tailscale network and is only accessible to trusted devices
2. All file transfers stay within your private Tailscale network
3. The app needs API access, not user delegation

## Security Considerations

- **Network Access**: The app is accessible to anyone who can reach it on your network. Consider:
  - Deploying it only on your Tailscale network (not publicly accessible)
  - Adding additional authentication if needed
  - Using Tailscale ACLs to restrict access
- **File Transfers**: All transfers use Tailscale's encrypted network
- **HTTPS**: Enforced via Fly.io configuration for production
- **Input Validation**: Device names are sanitized to prevent command injection

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

### Tailscale not connecting on Fly.io

- Verify `TAILSCALE_AUTH_KEY` is correct and not expired
- Check that the auth key is set as reusable
- View startup logs: `flyctl logs`
- SSH into the instance: `flyctl ssh console -C "tailscale status"`

### OAuth token errors

- Verify the OAuth client still exists in Tailscale admin
- Check that the OAuth client has `devices:read` permission
- Try regenerating the OAuth client credentials

## Project Structure

```
├── main.go              # Go web server with OAuth client credentials
├── templates/
│   └── index.html       # UI with device selector and drag-drop zone
├── go.mod               # Go module definition
├── Dockerfile           # Multi-stage build with Tailscale
├── start.sh             # Startup script for Tailscale + app
├── fly.toml             # Fly.io configuration
├── .gitignore           # Git ignore rules
└── README.md            # This file
```

## References

- [Tailscale OAuth Clients Documentation](https://tailscale.com/kb/1215/oauth-clients)
- [Tailscale API Documentation](https://tailscale.com/kb/1101/api)
- [Fly.io Documentation](https://fly.io/docs/)

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

**Sources:**
- [OAuth clients · Tailscale Docs](https://tailscale.com/kb/1215/oauth-clients)
- [Tailscale API · Tailscale Docs](https://tailscale.com/kb/1101/api)
