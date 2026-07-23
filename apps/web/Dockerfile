FROM node:24-alpine AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:24-alpine AS builder
WORKDIR /app
ARG TELESEC_API_PROXY_URL=http://api:8000
ENV TELESEC_API_PROXY_URL=$TELESEC_API_PROXY_URL
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:24-alpine AS runtime
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000
WORKDIR /app
RUN addgroup --system --gid 10001 telesec \
    && adduser --system --uid 10001 --ingroup telesec telesec
COPY --from=builder --chown=telesec:telesec /app/.next/standalone ./
COPY --from=builder --chown=telesec:telesec /app/.next/static ./.next/static
COPY --from=builder --chown=telesec:telesec /app/public ./public
USER telesec
EXPOSE 3000
CMD ["node", "server.js"]
