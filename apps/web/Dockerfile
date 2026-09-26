FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS builder
WORKDIR /app
ARG FORGESEC_API_PROXY_URL=http://api:8000
ARG NEXT_PUBLIC_FORGESEC_AGENT_SERVER_URL
ENV FORGESEC_API_PROXY_URL=$FORGESEC_API_PROXY_URL
ENV NEXT_PUBLIC_FORGESEC_AGENT_SERVER_URL=$NEXT_PUBLIC_FORGESEC_AGENT_SERVER_URL
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS runtime
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000
WORKDIR /app
RUN addgroup --system --gid 10001 forgesec \
    && adduser --system --uid 10001 --ingroup forgesec forgesec
COPY --from=builder --chown=forgesec:forgesec /app/.next/standalone ./
COPY --from=builder --chown=forgesec:forgesec /app/.next/static ./.next/static
COPY --from=builder --chown=forgesec:forgesec /app/public ./public
USER forgesec
EXPOSE 3000
CMD ["node", "server.js"]
