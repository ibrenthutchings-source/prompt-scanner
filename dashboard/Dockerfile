FROM node:22-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
# GATEWAY_UPSTREAM is substituted into this template at container start by
# nginx's built-in docker-entrypoint (any /etc/nginx/templates/*.template ->
# envsubst -> /etc/nginx/conf.d/*.conf), so the same image works whether the
# gateway is reached at gateway:8000 (Compose) or a Railway private domain.
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
ENV GATEWAY_UPSTREAM=gateway:8000
EXPOSE 80
