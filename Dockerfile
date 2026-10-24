FROM node:20-bookworm-slim

# Install Python 3 + SQLite3 for the high-concurrency WAL relational database daemon
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    sqlite3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
COPY server.js security.js database.js index.html admin_panel.html supabase_schema_and_rls.sql ./

# Create persistent volume mount point for SQLite WAL database & JWT secret
VOLUME ["/app/data"]

ENV NODE_ENV=production
ENV PORT=4000
ENV SQLITE_DB_PATH=/app/data/xyz_production.sqlite

EXPOSE 4000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4000/api/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "server.js"]
