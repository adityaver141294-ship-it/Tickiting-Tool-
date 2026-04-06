# ============================================================
# Stage 1 — Builder
# Install dependencies (needs build tools for native sqlite3)
# ============================================================
FROM node:20-alpine AS builder

# Build tools needed to compile sqlite3 native bindings
RUN apk add --no-cache python3 make g++

WORKDIR /build

# Install dependencies first (layer caching — only reinstalls if package.json changes)
COPY package*.json ./
RUN npm install --omit=dev

# ============================================================
# Stage 2 — Runtime
# Lean final image — no build tools, only the app + deps
# ============================================================
FROM node:20-alpine AS runtime

LABEL maintainer="TicketFlow"
LABEL description="TicketFlow — Enterprise Support & Issue Tracking System"
LABEL version="1.0"

# Create persistent data directory for SQLite database
RUN mkdir -p /data && chown -R node:node /data

WORKDIR /usr/src/app

# Copy installed node_modules from builder stage (no build tools!)
COPY --from=builder /build/node_modules ./node_modules

# Copy application source (chowned to unprivileged 'node' user)
COPY --chown=node:node . .

# Point SQLite to the persistent volume path
ENV DB_PATH=/data/database.sqlite
ENV NODE_ENV=production
ENV PORT=3000

# Run as non-root user for security
USER node

EXPOSE 3000

# Health check — Docker will restart the container if the app becomes unhealthy
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD wget -qO- http://localhost:3000 || exit 1

CMD ["node", "server.js"]
