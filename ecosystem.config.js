/**
 * PM2 Process Manager Configuration (ecosystem.config.js)
 * Keeps XYZ Games running 24/7 with automatic crash recovery, memory-limit restarts,
 * and structured production logging for 20,000+ daily traffic.
 *
 * Usage:
 *   npm install -g pm2
 *   pm2 start ecosystem.config.js --env production
 *   pm2 save && pm2 startup
 */

module.exports = {
  apps: [
    {
      name: 'xyz-games-production',
      script: './server.js',
      instances: 1, // Single master instance coordinates in-memory state + SSE broadcast + SQLite3 WAL daemon
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',
      env: {
        NODE_ENV: 'development',
        PORT: 4000
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 4000
      }
    }
  ]
};
