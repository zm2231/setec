FROM golang:1.26-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/setec ./cmd/setec

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/setec /setec

ENTRYPOINT ["/setec", "server"]
