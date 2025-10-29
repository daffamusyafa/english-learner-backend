# --- Stage 1: Build ---
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Ambil build argument untuk JWT_SECRET
ARG JWT_SECRET
ENV JWT_SECRET=$JWT_SECRET

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

# --- Stage 2: Final Image ---
FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/app .

# --- PERUBAHAN DI SINI ---
# Expose port yang digunakan aplikasi
EXPOSE 5000

# Command untuk menjalankan aplikasi
CMD ["./app"]
