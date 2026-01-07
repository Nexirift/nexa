FROM node:24-slim AS base

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
ENV CI=true

RUN corepack enable

RUN useradd --create-home --shell /bin/bash appuser

RUN apt-get update && \
    apt-get install -y clamav clamav-daemon curl && \
    rm -rf /var/lib/apt/lists/* && \
    # Ensure config files exist
    [ -f /etc/clamav/clamd.conf ] || cp /etc/clamav/clamd.conf.sample /etc/clamav/clamd.conf && \
    [ -f /etc/clamav/freshclam.conf ] || cp /etc/clamav/freshclam.conf.sample /etc/clamav/freshclam.conf && \
    mkdir -p /var/log/clamav /var/lib/clamav /var/run/clamav && \
    chown -R appuser:appuser /var/log/clamav /var/lib/clamav /etc/clamav /var/run/clamav

COPY . /app
WORKDIR /app

FROM base AS prod-deps
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --prod --frozen-lockfile

FROM base AS build
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile
RUN pnpm run build

FROM base

# Copy the start script
COPY docker-start.sh /app/docker-start.sh
RUN chmod +x /app/docker-start.sh

# Switch to non-root user
USER appuser

COPY --from=prod-deps /app/node_modules /app/node_modules
COPY --from=build /app/dist /app/dist

CMD ["/app/docker-start.sh"]
