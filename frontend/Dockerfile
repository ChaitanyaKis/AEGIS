# AEGIS Control Center — static dashboard for Cloud Run.
#
#   docker build -t aegis-ui .
#   docker run --rm -p 8080:8080 -e PORT=8080 -e BACKEND_HOST=<service>.run.app aegis-ui
#
# Two stages: build the SPA with Node, then serve it with nginx. The Node toolchain does
# not ship — the runtime image holds static files and a web server, nothing that can build
# or execute application code.
#
# Plain Dockerfile syntax throughout, no `RUN --mount`. Cloud Build's `gcr.io/cloud-builders/
# docker` step runs the legacy builder, which rejects BuildKit-only syntax outright.

FROM node:22.14-alpine AS build

WORKDIR /app

# Dependencies first, from the lockfile alone, so editing a component does not reinstall.
# `npm ci` installs exactly what package-lock.json records and fails if the two disagree —
# which is the property that makes a rebuild months from now produce the same bundle.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsconfig.app.json tsconfig.node.json vite.config.ts index.html ./
COPY public ./public
COPY src ./src

# VITE_API_BASE is left at its default of `/api`, which nginx proxies to the AEGIS service
# below. Baking an absolute backend URL into the bundle would pin the dashboard to one
# deployment and would put the call cross-origin, which is exactly what the proxy avoids.
RUN npm run build


FROM nginx:1.27-alpine AS runtime

# Cloud Run injects $PORT and will not honour nginx's compiled-in default of 80. The
# template is rendered at start-up rather than build time so one image runs on any port
# and against any backend.
ENV PORT=8080 \
    BACKEND_HOST=localhost

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

EXPOSE 8080

# The nginx image's own entrypoint runs envsubst over /etc/nginx/templates and writes the
# result to /etc/nginx/conf.d, so no custom start script is needed. It is restricted to the
# two names below: without the list, envsubst would also eat nginx's own `$uri` and
# `$host`, and the SPA fallback would silently stop working.
ENV NGINX_ENVSUBST_FILTER='^(PORT|BACKEND_HOST)$'
