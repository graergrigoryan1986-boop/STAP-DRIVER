FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY prisma ./prisma
RUN npx prisma generate
COPY src ./src
ENV NODE_ENV=production
EXPOSE 10000
CMD ["sh", "-c", "npx prisma db push && node src/server.js"]
