FROM node:20-bookworm
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY . .
# Значение попадает в слои образа и в docker history.
ARG STRIPE_SECRET_KEY=__FAKE_STRIPE_KEY_DOCKER__
ENV STRIPE_SECRET_KEY=$STRIPE_SECRET_KEY
CMD ["node", "server/index.js"]
