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
- 👁️ Screen wake lock to keep display on while shopping
- 🌙 Modern dark theme UI
- 📦 Progressive Web App (PWA) - install on mobile devices
- 🔢 Quantity tracking for each item
- 👥 User management with Admin/User roles

## Docker Compose (Recommended)

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
    ports:
      - 8888:8888
    volumes:
      - shopmode-data:/app/data
    restart: unless-stopped

volumes:
  shopmode-data:
```

Create `.env`:
```bash
SESSION_KEY=$(openssl rand -hex 32)
ADMIN_PASSWORD=$(openssl rand -base64 16)
```

Start:
```bash
docker-compose up -d
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SESSION_KEY` | - | **Required** - Random secret (use `openssl rand -hex 32`) |
| `DEFAULT_ADMIN_PASSWORD` | `admin` | Initial admin password - **change after first login!** |
| `HTTPS` | `true` | Set to `false` only for local development |
| `APP_TITLE` | `Shop Mode` | Application title shown in UI |
| `DEFAULT_ORGANIZATION` | `Default` | Name of the default organization |
| `DEFAULT_LIST` | `Shopping` | Name of the default list |

## Data Persistence

SQLite database with WAL mode enabled for better concurrency at `/app/data/shopping.db`

**Always mount to persist data:**
```bash
-v shopmode-data:/app/data
```

## Architecture

- **Runtime:** Go 1.23 with Chi router
- **Database:** SQLite3 with WAL mode
- **Frontend:** Vanilla JavaScript with WebSockets
- **Session Management:** Gorilla Sessions
- **Base Image:** debian:bookworm-slim

## Security (Production)

1. Generate secure `SESSION_KEY`: `openssl rand -hex 32`
2. Use strong admin password: `openssl rand -base64 16`
3. Run behind HTTPS reverse proxy (Caddy/Traefik/nginx)
4. Bind to localhost: `127.0.0.1:8888:8888`
5. Change admin password after first login
6. Run as non-root: `user: "1001:1001"`
7. Enable regular backups

## Reverse Proxy Examples

**Caddy:**
```caddy
shopmode.example.com {
    reverse_proxy localhost:8888
}
```

**nginx:**
```nginx
location / {
    proxy_pass http://127.0.0.1:8888;
}
location /ws {
    proxy_pass http://127.0.0.1:8888;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

## Backup
```bash
# Backup
docker cp shopmode:/app/data/shopping.db ./backup-$(date +%Y%m%d).db

# Restore
docker stop shopmode
docker cp backup.db shopmode:/app/data/shopping.db
docker start shopmode
```

## Upgrading
```bash
docker pull rochteja/shopmode:latest
docker stop shopmode && docker rm shopmode
docker run -d --name shopmode -p 8888:8888 \
  -e SESSION_KEY=your-key -v shopmode-data:/app/data \
  rochteja/shopmode:latest
```

Or with compose:
```bash
docker-compose pull && docker-compose up -d
```

## Troubleshooting

**Can't login:** Check `SESSION_KEY` is set and consistent, verify `HTTPS` setting  
**WebSocket issues:** Check reverse proxy WebSocket config, verify `Upgrade` headers  
**Database locked:** WAL mode enabled by default, ensure only one container accesses DB  
**Logs:** `docker logs shopmode`

## Support

- **GitHub:** https://github.com/rochteja/shopmode
- **Issues:** https://github.com/rochteja/shopmode/issues
- **Full Docs:** See GitHub repository README

## License

MIT License

---

**Pull:** `docker pull rochteja/shopmode:latest`