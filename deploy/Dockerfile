FROM node:22-alpine
RUN addgroup -S aegis && adduser -S aegis -G aegis
WORKDIR /app
COPY server/ /app/server/
COPY ui/ /app/ui/
RUN mkdir -p /app/server/data && chown -R aegis:aegis /app
USER aegis
EXPOSE 8787
ENV NODE_ENV=production
CMD ["node","/app/server/aegis-server.mjs","--config","/app/server/config.json"]
