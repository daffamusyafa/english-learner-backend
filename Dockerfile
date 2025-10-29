# --- Stage 1: Build ---
FROM golang:1.24-alpine AS builder

WORKDIR /app

ARG JWT_SECRET
ENV JWT_SECRET=$JWT_SECRET

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

# --- Stage 2: Final Image ---
FROM alpine:latest

WORKDIR /root/

# ✅ FIX TIMEZONE ERROR
RUN apk add --no-cache tzdata
ENV TZ=Asia/Jakarta

COPY --from=builder /app/app .

EXPOSE 5000

CMD ["./app"]
