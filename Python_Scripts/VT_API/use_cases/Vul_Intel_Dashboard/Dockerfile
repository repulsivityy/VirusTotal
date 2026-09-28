# Stage 1: Build stage
FROM node:22-alpine AS builder

WORKDIR /app

ENV NPM_CONFIG_UPDATE_NOTIFIER=false

# Copy package files
COPY package*.json ./

# Install all dependencies (including devDependencies for Vite + esbuild)
RUN npm install --no-audit --no-fund

# Copy codebase
COPY . .

# Build both static client assets and bundled server code
RUN npm run build

# Stage 2: Production runtime stage
FROM node:22-alpine AS runner

WORKDIR /app

# Set production environment
ENV NODE_ENV=production
ENV PORT=8080
ENV NPM_CONFIG_UPDATE_NOTIFIER=false

# Copy package files to install production dependencies
COPY package*.json ./

# Install only production runtime dependencies (express, dotenv, @google/genai)
RUN npm install --omit=dev --no-audit --no-fund

# Copy build output (dist directory containing client assets & server bundle)
COPY --from=builder /app/dist ./dist

# Expose port
EXPOSE 8080

# Start the server using node
CMD ["node", "dist/server.cjs"]
