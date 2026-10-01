# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kaircd ./cmd/kaircd

FROM scratch
COPY --from=build /out/kaircd /kaircd
USER 65532:65532
EXPOSE 6667 8080
ENTRYPOINT ["/kaircd"]
