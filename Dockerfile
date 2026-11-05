# Deeptera — container statis (tanpa backend).
# Build:  docker build -t deeptera:latest .
# Run:    docker run -d --name deeptera -p 8787:8787 deeptera:latest

FROM node:22-alpine

WORKDIR /app

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8787 \
    IRIS_IN_CONTAINER=1

COPY index.html styles.css tenants.css app.js extract.js numbering.js config.js server.js ./

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8787/healthz >/dev/null || exit 1

USER node

CMD ["node", "server.js"]
