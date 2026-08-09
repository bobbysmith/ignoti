FROM node:22-alpine AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

FROM base AS builder
WORKDIR /build

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY packages/shared/package.json ./packages/shared/
COPY packages/server/package.json ./packages/server/

RUN pnpm install --frozen-lockfile

COPY packages/shared ./packages/shared
COPY packages/server ./packages/server

RUN pnpm --filter @ignoti/shared build
RUN pnpm --filter @ignoti/server build

RUN pnpm --filter @ignoti/server deploy --prod --legacy /app

FROM node:22-alpine AS runner
WORKDIR /app

RUN addgroup -S ignoti && adduser -S ignoti -G ignoti

COPY --from=builder --chown=ignoti:ignoti /app ./
COPY --from=builder --chown=ignoti:ignoti /build/packages/server/src/db/migrations ./dist/db/migrations

USER ignoti

EXPOSE 8787
ENV NODE_ENV=production

CMD ["sh", "-c", "node dist/db/migrate.js && node dist/index.js"]
