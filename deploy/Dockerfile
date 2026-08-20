# Two-stage build so `docker build` is the only tool a Docker host needs.
# Stage one builds ui/index.html from src/ (that file is generated and
# gitignored, so a fresh clone never has it on disk); stage two ships only
# the server and the built console, not the toolchain that made them.

FROM node:22-alpine AS build
WORKDIR /app
COPY src/ /app/src/
COPY build.mjs /app/build.mjs
RUN node build.mjs

FROM node:22-alpine
RUN addgroup -S aegis && adduser -S aegis -G aegis
WORKDIR /app
COPY server/ /app/server/
COPY --from=build /app/ui/ /app/ui/
RUN mkdir -p /app/server/data && chown -R aegis:aegis /app
USER aegis
EXPOSE 8787
ENV NODE_ENV=production
CMD ["node","/app/server/aegis-server.mjs","--config","/app/server/config.json"]
