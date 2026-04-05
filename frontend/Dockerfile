FROM node:20-alpine
WORKDIR /app
COPY package*.json tsconfig.json vite.config.ts ./
RUN npm install
COPY . .
CMD ["npm", "run", "dev"]
