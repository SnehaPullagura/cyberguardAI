# --- Stage 1: Build Frontend Assets ---
FROM node:20-alpine as builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci

COPY . .
RUN npm run build

# --- Stage 2: Hardened Production Nginx ---
FROM nginx:1.25-alpine as runtime

# Remove default nginx configurations
RUN rm -rf /etc/nginx/conf.d/*

# Copy built static assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy production Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Security headers & user
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s \
    CMD wget --quiet --tries=1 --spider http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
