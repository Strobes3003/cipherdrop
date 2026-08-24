# CipherDrop

CipherDrop is a secure, temporary secret-sharing platform inspired by PrivateBin.

## Features

- Client-side AES-256-GCM encryption using the Web Crypto API
- Encryption key kept in the URL fragment
- Secret expiration and maximum view limits
- Burn-after-reading
- Optional password protection
- Server-side policy enforcement
- Secret management and deletion
- Sensitive-data detection and security scoring

## Technology Stack

- Frontend: React, Vite, JavaScript, Web Crypto API, Vitest
- Backend: Java 21, Spring Boot, Spring Data JPA, Hibernate, Maven
- Database: PostgreSQL

## Security Model

The browser encrypts secrets using AES-256-GCM before sending ciphertext to the backend.

The encryption key remains in the URL fragment and is not sent to the backend in normal HTTP requests.

The backend stores ciphertext and IV and enforces expiration, password verification, maximum views, burn-after-reading, and management-token validation.

## Setup

### Prerequisites

- Java 21+
- Node.js
- pnpm
- PostgreSQL

### Clone

git clone https://github.com/Strobes3003/cipherdrop.git
cd cipherdrop

### Database

Create a PostgreSQL database named cipherdrop.

### Database Password

Set the PostgreSQL password in Git Bash:

export CIPHERDROP_DB_PASSWORD="your_postgres_password"

### Backend

cd backend
./mvnw spring-boot:run

Backend runs on http://localhost:8080

### Frontend

cd frontend
pnpm install
pnpm dev

Frontend runs on http://localhost:5173

## Testing

Backend:
./mvnw test

Frontend:
pnpm test

Production build:
pnpm build

## Verification

CipherDrop has been tested end-to-end, including secret creation, encryption, sharing, decryption, password protection, expiration, view limits, burn-after-reading, management, deletion, sensitive-data detection, and security advisor functionality.

## Security Note

Anyone who obtains the complete share link may be able to access the secret after satisfying its configured access policy. Share CipherDrop links carefully.
