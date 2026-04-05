FROM node:20-alpine
WORKDIR /app
COPY frontend/package*.json frontend/tsconfig.json frontend/vite.config.ts ./
RUN npm install
COPY frontend /app
CMD ["npm", "run", "dev"]
