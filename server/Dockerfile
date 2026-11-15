FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY src/tunnel-policy.cjs src/tunnel-policy.cjs
COPY server/server.cjs server/server.cjs
USER node
EXPOSE 3000
CMD ["node", "server/server.cjs"]
