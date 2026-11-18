# No frontend directive: nothing here needs a newer Dockerfile frontend than the
# builder's own, and an unpinned one would be fetched by mutable tag on every build.

# Build context: the repository root (Railway: source.rootDirectory unset,
# build.dockerfilePath testui/Dockerfile; locally: docker build -f testui/Dockerfile .).
# The testui module requires the root module through `replace => ../`.

# golang:1.27 (multi-arch index, go1.27.4, resolved 2026-11-18 with `docker buildx imagetools inspect golang:1.27`)
FROM golang:1.27@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS build
# Build with the pinned image's Go only: a go.mod above it fails here instead of downloading a toolchain.
ENV GOTOOLCHAIN=local
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
