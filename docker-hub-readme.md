# Shop Mode App

A modern, real-time collaborative shopping list application with multi-user support, WebSocket sync, and a mobile-friendly PWA interface.

## Quick Start

```bash
docker run -d \
  --name shopmode \
  -p 8888:8888 \
  -e SESSION_KEY=$(openssl rand -hex 32) \
  -e DEFAULT_ADMIN_PASSWORD=$(openssl rand -base64 16) \
  -v shopmode-data:/app/data \
  --restart unless-stopped \
  rochteja/shopmode:latest
```

Access at `http://localhost:8888`

⚠️ **Save your admin password from the command above!**

## Features

- 🔐 Multi-tenant authentication with role-based access
- 📋 Multiple shopping lists per organization
- 🏷️ Custom categories for organizing items
- ⚡ Real-time WebSocket sync across all devices
- 📱 Shopping Mode - large touch-friendly interface for in-store use
- 💤 Screen wake lock to keep display on while shopping
- 🌙 Modern dark theme UI
- 📦 Progressive Web App (PWA) - install on mobile devices
- 🔢 Quantity tracking for each item
- 👥 User management with Admin/User roles

## Production Deployment

### Docker Compose (Recommended)

Create `docker-compose.yml`:

```yaml
services:
  shopmode:
    image: rochteja/shopmode:latest
    container_name: shopmode
    user: "1001:1001"
    environment:
      - HTTPS=true
      - SESSION_KEY=${SESSION_KEY}
      - DEFAULT_ADMIN_PASSWORD=${ADMIN_PASSWORD}
      - APP_TITLE=Shop Mode
      - DEFAULT_ORGANIZATION=MyFamily
      - DEFAULT_LIST=Shopping
      - DEFAULT_ADMIN_USERNAME=admin
    ports:
      - "127.0.0.1:8888:8888"
    volumes:
      - shopmode-data:/app/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8888/"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  shopmode-data:
```

Create `.env` file with secure secrets:

```bash
SESSION_KEY=$(openssl rand -hex 32)
ADMIN_PASSWORD=$(openssl rand -base64 16)
```

Start the application:

```bash
docker-compose up -d
```

## Environment Variables

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SESSION_KEY` | - | **Yes** | Random secret for session encryption (use `openssl rand -hex 32`) |
| `DEFAULT_ADMIN_PASSWORD` | `admin` | No | Initial admin password - **change after first login!** |
| `HTTPS` | `true` | No | Set to `false` only for local development without reverse proxy |
| `APP_TITLE` | `Shop Mode` | No | Application title shown in UI |
| `DEFAULT_ORGANIZATION` | `Default` | No | Name of the default organization |
| `DEFAULT_LIST` | `Shopping` | No | Name of the default shopping list |
| `DEFAULT_ADMIN_USERNAME` | `admin` | No | Initial admin username |

## Volumes

The application stores all data in SQLite at `/app/data/shopping.db`

**Always mount this directory to persist your data:**

```bash
-v shopmode-data:/app/data
```

Or bind to a local directory:

```bash
-v ./data:/app/data
```

## Ports

- **8888** - HTTP web interface and WebSocket connections

## Architecture

- **Runtime:** Go 1.21 with embedded templates and static assets
- **Database:** SQLite3 (single file, no external DB required)
- **Frontend:** Vanilla JavaScript with WebSockets
- **Base Image:** debian:bookworm-slim

## Security Best Practices

### ⚠️ Critical for Production

1. **Generate a secure SESSION_KEY** (32+ bytes):
   ```bash
   openssl rand -hex 32
   ```

2. **Use a strong admin password**:
   ```bash
   openssl rand -base64 16
   ```

3. **Run behind HTTPS reverse proxy** (Caddy, Traefik, nginx)

4. **Bind to localhost** when using reverse proxy:
   ```yaml
   ports:
     - "127.0.0.1:8888:8888"
   ```

5. **Change admin password** immediately after first login

6. **Run as non-root user**:
   ```yaml
   user: "1001:1001"
   ```

7. **Enable regular backups** of SQLite database

## Reverse Proxy Examples

### Caddy (Automatic HTTPS)

```caddy
shopmode.example.com {
    reverse_proxy localhost:8888
}
```

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name shopmode.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:8888;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /ws {
        proxy_pass http://127.0.0.1:8888;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### Traefik

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.shopmode.rule=Host(`shopmode.example.com`)"
  - "traefik.http.routers.shopmode.tls.certresolver=letsencrypt"
  - "traefik.http.services.shopmode.loadbalancer.server.port=8888"
```

## Backup and Restore

### Backup

```bash
# Using docker cp
docker cp shopmode:/app/data/shopping.db ./backup-$(date +%Y%m%d).db

# Using docker-compose
docker-compose exec shopmode cat /app/data/shopping.db > backup.db
```

### Restore

```bash
# Stop container
docker stop shopmode

# Restore database
docker cp backup.db shopmode:/app/data/shopping.db

# Start container
docker start shopmode
```

### Automated Backups

```bash
# Add to crontab for daily backups at 2 AM
0 2 * * * docker cp shopmode:/app/data/shopping.db /backups/shopping-$(date +\%Y\%m\%d).db
```

## Health Check

The container includes a built-in health check:

```bash
docker ps
# Shows "healthy" status when running correctly
```

Manual health check:

```bash
docker exec shopmode wget -q -O- http://localhost:8888/ > /dev/null && echo "OK" || echo "FAIL"
```

## Upgrading

```bash
# Pull latest image
docker pull rochteja/shopmode:latest

# Stop and remove old container (data persists in volume)
docker stop shopmode
docker rm shopmode

# Start new container with same volume
docker run -d \
  --name shopmode \
  -p 8888:8888 \
  -e SESSION_KEY=your-existing-key \
  -v shopmode-data:/app/data \
  --restart unless-stopped \
  rochteja/shopmode:latest
```

Or with docker-compose:

```bash
docker-compose pull
docker-compose up -d
```

## Troubleshooting

### Can't Login

- Ensure `SESSION_KEY` is set and doesn't change between restarts
- Verify `HTTPS` setting matches your deployment
- Clear browser cookies and try again
- Check logs: `docker logs shopping`

### WebSocket Not Connecting

- Check reverse proxy WebSocket configuration
- Verify `Upgrade` headers are being passed
- Ensure firewall allows WebSocket connections
- Check browser console for errors

### Database Locked

- Ensure only one container accesses the database
- Check volume permissions
- Stop container, backup DB, restore to new volume

### Container Won't Start

```bash
# Check logs
docker logs shopping

# Common issues:
# - Missing SESSION_KEY
# - Port already in use
# - Volume permission issues
```

## Usage

### First-Time Setup

1. Login with admin credentials (from your environment variables)
2. Change admin password in Settings
3. Create user accounts for family/team members
4. Customize categories if needed
5. Create additional lists

### Multi-User Collaboration

- All users in an organization share the same lists
- Real-time sync via WebSocket
- Green dot shows when others are connected
- Each item tracks who added it

### Shopping Mode

- Toggle shopping cart icon for large, touch-friendly interface
- Perfect for use in stores
- Auto-exits when all items are checked

### PWA Installation

**iOS:** Safari → Share → Add to Home Screen  
**Android:** Chrome → Menu → Install App

## Support

- **GitHub:** https://github.com/rochteja/shopmode
- **Documentation:** Full README in GitHub repository

## License

MIT License - See LICENSE file in repository

---

**Pull Command:**
```bash
docker pull rochteja/shopmode:latest
```