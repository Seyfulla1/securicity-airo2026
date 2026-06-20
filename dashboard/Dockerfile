# Node 20 on Alpine = a tiny production image.
FROM node:20-alpine

WORKDIR /app

# Install dependencies first so this layer is cached until package.json changes.
# We have no package-lock.json in this starter, so we use `npm install`.
# --omit=dev skips devDependencies (we have none, but it's good production hygiene).
COPY package.json ./
RUN npm install --omit=dev

# Copy the server and the static front-end.
COPY server.js ./
COPY public ./public

EXPOSE 3000
CMD ["node", "server.js"]
