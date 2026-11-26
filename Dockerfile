FROM node:22-alpine

WORKDIR /app

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8787 \
    DATA_DIR=/app/data \
    IRIS_IN_CONTAINER=1

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY index.html styles.css tenants.css favicon.svg app.js triage-ui.js extract.js numbering.js config.js db.js auth.js triage.js server.js ./

RUN mkdir -p /app/data && chown -R node:node /app

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8787/healthz >/dev/null || exit 1

USER node

CMD ["node", "server.js"]
