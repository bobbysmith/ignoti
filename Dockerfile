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

RUN pnpm --filter @ghostid/shared build
RUN pnpm --filter @ghostid/server build

RUN pnpm --filter @ghostid/server deploy --prod --legacy /app

FROM node:22-alpine AS runner
WORKDIR /app

RUN addgroup -S ghostid && adduser -S ghostid -G ghostid

COPY --from=builder --chown=ghostid:ghostid /app ./
COPY --from=builder --chown=ghostid:ghostid /build/packages/server/src/db/migrations ./dist/db/migrations

USER ghostid

EXPOSE 8787
ENV NODE_ENV=production

CMD ["sh", "-c", "node dist/db/migrate.js && node dist/index.js"]
