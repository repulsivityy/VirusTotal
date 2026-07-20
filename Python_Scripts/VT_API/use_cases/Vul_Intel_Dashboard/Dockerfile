# Stage 1: Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies
RUN npm install

# Copy codebase
COPY . .

# Build both static client assets and bundled server code
RUN npm run build

# Stage 2: Production runtime stage
FROM node:20-alpine AS runner

WORKDIR /app

# Set production environment
ENV NODE_ENV=production
ENV PORT=8080

# Copy package files to install production dependencies
COPY package*.json ./

# Install only production dependencies
RUN npm install --omit=dev

# Copy build output (dist directory containing client assets & server bundle)
COPY --from=builder /app/dist ./dist

# Expose port
EXPOSE 8080

# Start the server using node
CMD ["node", "dist/server.cjs"]
