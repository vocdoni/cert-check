# syntax=docker/dockerfile:1

# Build context: the repository root (Railway: source.rootDirectory unset,
# build.dockerfilePath testui/Dockerfile; locally: docker build -f testui/Dockerfile .).
# The testui module requires the root module through `replace => ../`.

# golang:1.27 (multi-arch index, resolved 2026-10-31 with `docker buildx imagetools inspect golang:1.27`)
FROM golang:1.27@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY testui/go.mod testui/go.sum ./testui/
WORKDIR /src/testui
RUN go mod download
WORKDIR /src
COPY . .
WORKDIR /src/testui
ARG RAILWAY_GIT_COMMIT_SHA=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${RAILWAY_GIT_COMMIT_SHA}" -o /out/cert-check .

# gcr.io/distroless/static-debian12:nonroot (multi-arch index, resolved 2026-10-31 with
# `docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot`)
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/cert-check /cert-check
EXPOSE 8080 8443
ENTRYPOINT ["/cert-check"]
