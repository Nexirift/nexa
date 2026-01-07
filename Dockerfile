FROM node:22-slim AS base

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
ENV CI=true

RUN corepack enable

RUN apt-get update && \
    apt-get install -y \
        clamav clamav-daemon \
        curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY . /app
WORKDIR /app

FROM base AS prod-deps
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --prod --frozen-lockfile

FROM base AS build
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile
RUN pnpm run build

FROM base

COPY --from=prod-deps /app/node_modules /app/node_modules
COPY --from=build /app/dist /app/dist

# Copy the start script
COPY docker-start.sh /app/docker-start.sh
RUN chmod +x /app/docker-start.sh

# Ensure ClamAV directories exist and have correct permissions
RUN [ -f /etc/clamav/clamd.conf ] || cp /etc/clamav/clamd.conf.sample /etc/clamav/clamd.conf && \
    [ -f /etc/clamav/freshclam.conf ] || cp /etc/clamav/freshclam.conf.sample /etc/clamav/freshclam.conf && \
    mkdir -p /var/log/clamav /var/lib/clamav /var/run/clamav && \
    chown -R clamav:clamav /var/log/clamav /var/lib/clamav /etc/clamav /var/run/clamav

USER clamav

CMD ["/app/docker-start.sh"]
