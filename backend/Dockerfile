FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY prisma ./prisma
RUN npx prisma generate
COPY src ./src
COPY public ./public
RUN npm prune --omit=dev
ENV NODE_ENV=production
EXPOSE 10000
CMD ["sh", "-c", "npx prisma db execute --file prisma/preflight.sql && npx prisma db push --accept-data-loss && node src/server.js"]
