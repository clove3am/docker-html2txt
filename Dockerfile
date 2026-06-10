# ---- Stage 1: Build ----
# Use the official Go image as a build environment
FROM golang:1.26-alpine AS builder

# Install build dependencies, including git and lynx
RUN apk add --no-cache git lynx

# Set the working directory
WORKDIR /app

# Copy the Go module files. The wildcard ensures this works
# whether go.sum exists or not.
COPY go.* ./
RUN go mod download

# Copy the source code
COPY main.go ./

# Build the Go app, creating a static binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app/html2txt .


# ---- Stage 2: Final Image ----
# Use a minimal base image for the final product.
FROM alpine:3.24.0

# We must install lynx again in our final image as it's a runtime dependency.
RUN apk add --no-cache lynx

# Copy only the compiled binary from the builder stage.
COPY --from=builder /app/html2txt /html2txt

# Expose the port the app runs on.
EXPOSE 8080

# The command to run when the container starts.
CMD ["/html2txt"]
