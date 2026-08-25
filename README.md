# CipherDrop

CipherDrop is a secure, temporary secret-sharing platform inspired by PrivateBin.

It allows users to create encrypted secrets that can be shared through temporary links. Secrets can expire automatically, be limited to a maximum number of views, or be configured to burn after being read.

CipherDrop uses **client-side encryption** so that the plaintext secret and encryption key are not sent to the backend.

---

## Features

- Client-side AES-256-GCM encryption using the Web Crypto API
- Encryption key stored in the URL fragment
- Backend stores encrypted ciphertext and IV
- Secret expiration
- Maximum view limits
- Burn-after-reading
- Optional password protection
- Server-side access-policy enforcement
- Management-token validation
- Secret management and deletion
- QR-code sharing
- Sensitive-data detection
- Security Advisor and security scoring
- React frontend with Vite
- Spring Boot REST backend
- PostgreSQL persistence
- Local development environment
- Production deployment support
- Vercel SPA routing configuration
- Docker configuration for backend deployment

---

# Security Architecture

CipherDrop separates **encryption** from **storage and access control**.

The browser encrypts the secret before it is sent to the backend.

```text
                         CipherDrop

Plaintext Secret
       |
       v
+-------------------+
| React Frontend    |
| Web Crypto API    |
+-------------------+
       |
       | AES-256-GCM
       v
+-------------------+
| Ciphertext + IV   |
+-------------------+
       |
       | HTTPS / REST API
       v
+-------------------+
| Spring Boot       |
| Backend           |
+-------------------+
       |
       v
+-------------------+
| PostgreSQL        |
+-------------------+
```

### Encryption Key

The encryption key remains on the client and is stored in the URL fragment.

A sharing URL has the following conceptual structure:

```text
https://your-domain/s/{secret-id}#{encryption-key}
```

The URL fragment (`#...`) is handled by the browser and is not included in normal HTTP requests sent to the backend.

Therefore:

- The backend receives encrypted ciphertext.
- The backend receives the IV and required policy metadata.
- The backend does not receive the plaintext secret.
- The backend does not receive the client-side encryption key.

When the recipient opens the sharing link, the frontend extracts the secret ID and encryption key, retrieves the encrypted data, and decrypts it locally.

---

# Architecture

```text
                         CipherDrop
                             |
              +--------------+--------------+
              |                             |
              v                             v
         React/Vite                    Spring Boot
          Frontend                       Backend
              |                             |
              | /api/*                      |
              +---------------------------->|
                                            |
                                            v
                                      PostgreSQL
```

## Local Architecture

```text
Browser
   |
   v
React + Vite
localhost:5173
   |
   | /api/*
   | Vite development proxy
   v
Spring Boot
localhost:8080
   |
   v
PostgreSQL
localhost:5432
database: cipherdrop
```

The frontend Vite configuration proxies `/api` requests to:

```text
http://localhost:8080
```

## Production Architecture

```text
Browser
   |
   v
Vercel
React/Vite Frontend
   |
   | REST API
   v
Production Backend
Spring Boot
   |
   v
Production PostgreSQL
```

The backend is also configured to use the deployment platform's `PORT` environment variable, with `8080` as the local/default port.

---

# Project Structure

```text
cipherdrop/
│
├── backend/
│   ├── src/
│   │   ├── main/
│   │   │   ├── java/
│   │   │   │   └── com/cipherdrop/
│   │   │   │       ├── config/
│   │   │   │       ├── controller/
│   │   │   │       ├── dto/
│   │   │   │       ├── entity/
│   │   │   │       ├── enums/
│   │   │   │       ├── exception/
│   │   │   │       ├── policy/
│   │   │   │       ├── repository/
│   │   │   │       └── service/
│   │   │   │
│   │   │   └── resources/
│   │   │       └── application.properties
│   │   │
│   │   └── test/
│   │
│   ├── Dockerfile
│   ├── pom.xml
│   ├── mvnw
│   └── mvnw.cmd
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── utils/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── styles.css
│   │
│   ├── package.json
│   ├── pnpm-lock.yaml
│   ├── vercel.json
│   └── vite.config.js
│
├── docs/
│   ├── architecture.md
│   ├── frontend-decisions.md
│   └── ...
│
└── README.md
```

---

# Technology Stack

## Frontend

- React 19
- Vite 7
- JavaScript
- React Router
- Web Crypto API
- Vitest
- QRCode React

## Backend

- Java 17
- Spring Boot 4
- Spring Web MVC
- Spring Data JPA
- Hibernate
- Spring Security Crypto
- Bean Validation
- Maven
- Lombok

## Database

- PostgreSQL

## Deployment

- Vercel-compatible frontend deployment
- Docker-compatible backend deployment
- PostgreSQL production database

---

# Local Development

## Prerequisites

Install:

- Git
- Java 17+
- Node.js
- pnpm
- PostgreSQL

PostgreSQL 17 is suitable for local development.

---

## 1. Clone the Repository

```bash
git clone https://github.com/Strobes3003/cipherdrop.git
cd cipherdrop
```

---

## 2. Configure PostgreSQL

Make sure PostgreSQL is running.

The default local database configuration is:

```text
Host: localhost
Port: 5432
Database: cipherdrop
Username: postgres
```

Create the database if it does not already exist:

```sql
CREATE DATABASE cipherdrop;
```

Verify the database:

```bash
psql -U postgres -h localhost -p 5432 -l
```

On Windows, if `psql` is not available in PATH, use the PostgreSQL installation path, for example:

```bash
"/c/Program Files/PostgreSQL/17/bin/psql.exe" -U postgres -h localhost -p 5432 -l
```

Check whether PostgreSQL is accepting connections:

```bash
pg_isready -h localhost -p 5432
```

Expected result:

```text
localhost:5432 - accepting connections
```

---

# 3. Configure Backend Environment Variables

The backend reads its database configuration from environment variables.

The required variables are:

```text
DATABASE_URL
DATABASE_USERNAME
DATABASE_PASSWORD
```

For local development:

```text
DATABASE_URL=jdbc:postgresql://localhost:5432/cipherdrop
DATABASE_USERNAME=postgres
DATABASE_PASSWORD=your_postgres_password
```

### Git Bash

```bash
export DATABASE_URL="jdbc:postgresql://localhost:5432/cipherdrop"
export DATABASE_USERNAME="postgres"
export DATABASE_PASSWORD="your_postgres_password"
```

You can verify the configuration without printing the actual password:

```bash
echo "DATABASE_URL=$DATABASE_URL"
echo "DATABASE_USERNAME=$DATABASE_USERNAME"
echo "DATABASE_PASSWORD=[SET]"
```

Expected:

```text
DATABASE_URL=jdbc:postgresql://localhost:5432/cipherdrop
DATABASE_USERNAME=postgres
DATABASE_PASSWORD=[SET]
```

### Important

`DATABASE_URL` must use the JDBC PostgreSQL format:

```text
jdbc:postgresql://localhost:5432/cipherdrop
```

Do **not** use:

```text
postgresql://localhost:5432/cipherdrop
```

Never commit database credentials to GitHub.

---

# 4. Start the Backend

Open a terminal:

```bash
cd ~/cipherdrop/backend
```

Run Spring Boot:

```bash
./mvnw spring-boot:run
```

On Windows:

```bash
mvnw.cmd spring-boot:run
```

The backend runs on:

```text
http://localhost:8080
```

The backend uses:

```text
server.port=${PORT:8080}
```

This means a deployment platform can provide its own `PORT`, while local development defaults to port `8080`.

---

# 5. Start the Frontend

Open a second terminal:

```bash
cd ~/cipherdrop/frontend
```

Install dependencies:

```bash
pnpm install
```

Start the Vite development server:

```bash
pnpm dev
```

The frontend runs on:

```text
http://localhost:5173
```

Open the application at:

```text
http://localhost:5173
```

---

# Local API Flow

The Vite development server is configured to proxy `/api` requests to the Spring Boot backend.

```text
Browser
   |
   v
http://localhost:5173
   |
   | /api/*
   v
http://localhost:8080
   |
   v
PostgreSQL
```

This keeps frontend API requests consistent during local development.

---

# Using CipherDrop

## Create a Secret

1. Open the CipherDrop frontend.
2. Enter the secret.
3. Configure the desired access policies.
4. Create the secret.
5. The browser encrypts the secret using AES-256-GCM.
6. The encrypted data is sent to the backend.
7. CipherDrop generates a sharing URL.

---

## Share a Secret

The sharing URL contains the secret identifier and the client-side encryption key.

Conceptually:

```text
/s/{secret-id}#{encryption-key}
```

The complete URL must be shared with the intended recipient.

Treat the complete URL as sensitive because possession of the URL may provide access to the secret according to its configured policy.

---

## Access a Secret

When a recipient opens the sharing link:

1. The frontend reads the secret ID.
2. The frontend reads the encryption key from the URL fragment.
3. The frontend requests the encrypted secret.
4. The backend validates the applicable access policy.
5. The backend returns the encrypted data.
6. The frontend decrypts the ciphertext locally.
7. The plaintext is displayed to the recipient.

---

# Secret Policies

CipherDrop supports several access-control policies.

## Expiration

Secrets can be configured to expire after a specified period.

## Maximum Views

Secrets can be limited to a maximum number of successful views.

## Burn After Reading

A secret can be consumed after successful access.

## Password Protection

Secrets can optionally require password verification before access.

Passwords are not stored as plaintext.

## Management

Management-token validation is used for protected secret-management operations such as managing or deleting a secret.

---

# Backend Responsibilities

The Spring Boot backend is responsible for:

- Storing encrypted secret data
- Storing the IV required for decryption
- Managing secret identifiers
- Enforcing expiration
- Enforcing maximum view limits
- Enforcing burn-after-reading
- Handling password verification
- Validating management tokens
- Returning encrypted secret data
- Providing REST API functionality

The backend does not perform the client-side AES-256-GCM encryption or receive the encryption key from the URL fragment.

---

# Frontend Security Features

CipherDrop also includes client-side security tooling.

## Sensitive Data Detection

The frontend includes sensitive-data detection functionality that can identify potentially sensitive content before it is shared.

## Security Advisor

The frontend includes a Security Advisor and security-scoring functionality intended to provide users with security guidance before sharing secrets.

These features are implemented in the frontend and include automated tests.

---

# QR Code Sharing

CipherDrop supports QR-code sharing.

The frontend uses:

```text
qrcode.react
```

to generate QR representations of secret-sharing links.

This allows users to transfer a complete secret-sharing URL through a QR code.

As with normal links, the complete QR code should be treated as sensitive.

---

# Testing

## Backend Tests

From the backend directory:

```bash
cd backend
./mvnw test
```

## Frontend Tests

From the frontend directory:

```bash
cd frontend
pnpm test
```

## Frontend Production Build

```bash
cd frontend
pnpm build
```

## Frontend Test Watch Mode

```bash
pnpm test:watch
```

---

# Production Deployment

CipherDrop is structured to support separate frontend and backend deployment.

```text
                 Production

                   Browser
                      |
                      v
                   Vercel
                      |
                      | API requests
                      v
              Spring Boot Backend
                      |
                      v
              PostgreSQL Database
```

---

## Frontend Deployment

The frontend is configured for Vercel-compatible deployment.

The repository contains:

```text
frontend/vercel.json
```

The project also includes SPA routing configuration so that client-side routes can be served correctly when directly accessed in production.

---

## Backend Deployment

The backend includes a Dockerfile:

```text
backend/Dockerfile
```

The application also supports deployment platforms that provide a dynamic `PORT` environment variable.

The backend configuration is:

```properties
server.port=${PORT:8080}
```

Therefore:

- Local development defaults to port `8080`.
- A cloud deployment platform can provide its own port through `PORT`.

---

# Production Environment Variables

Production database configuration should be supplied through the deployment platform's environment-variable settings.

The backend expects:

```text
DATABASE_URL
DATABASE_USERNAME
DATABASE_PASSWORD
```

For a production PostgreSQL database, `DATABASE_URL` must be a JDBC PostgreSQL URL.

Example format:

```text
jdbc:postgresql://<host>:<port>/<database>
```

Do not place production credentials in:

- `application.properties`
- `README.md`
- frontend source code
- Git history
- public configuration files

---

# Local vs Production

| Component | Local | Production |
|---|---|---|
| Frontend | Vite | Vercel |
| Frontend Port | 5173 | Platform assigned |
| Backend | Spring Boot | Docker/cloud deployment |
| Backend Port | 8080 | `PORT` |
| Database | PostgreSQL | PostgreSQL |
| Database Host | localhost | Production database host |
| Encryption | Browser | Browser |
| Encryption Key | URL fragment | URL fragment |

Environment-specific values are supplied externally rather than hardcoded into the application.

---

# Security Considerations

CipherDrop's client-side encryption model is designed to prevent the backend from receiving plaintext secrets or the client-side encryption key.

However, users should still treat secret-sharing links as sensitive.

### Users should:

- Share secret links only with intended recipients.
- Treat complete sharing URLs as sensitive.
- Avoid posting secret links publicly.
- Avoid exposing secret links in screenshots or logs.
- Use HTTPS in production.
- Keep database credentials secure.
- Never commit credentials to GitHub.

Anyone who obtains the complete secret-sharing URL may potentially access the secret, subject to the configured access policies.

---

# Troubleshooting

## Backend: `'url' must start with "jdbc"`

This means `DATABASE_URL` is incorrectly configured.

Use:

```text
jdbc:postgresql://localhost:5432/cipherdrop
```

Not:

```text
postgresql://localhost:5432/cipherdrop
```

---

## PostgreSQL Is Not Running

Check:

```bash
pg_isready -h localhost -p 5432
```

Expected:

```text
localhost:5432 - accepting connections
```

---

## Database Does Not Exist

List databases:

```bash
psql -U postgres -h localhost -p 5432 -l
```

Create the database if necessary:

```sql
CREATE DATABASE cipherdrop;
```

---

## Frontend Cannot Reach Backend

Make sure the backend is running:

```text
http://localhost:8080
```

Then make sure the frontend is running:

```text
http://localhost:5173
```

The Vite configuration proxies:

```text
/api/*
```

to:

```text
http://localhost:8080
```

---

# Development Workflow

Run the backend and frontend in separate terminals.

### Terminal 1 — Backend

```bash
cd ~/cipherdrop/backend

export DATABASE_URL="jdbc:postgresql://localhost:5432/cipherdrop"
export DATABASE_USERNAME="postgres"
export DATABASE_PASSWORD="your_postgres_password"

./mvnw spring-boot:run
```

### Terminal 2 — Frontend

```bash
cd ~/cipherdrop/frontend

pnpm install
pnpm dev
```

Then open:

```text
http://localhost:5173
```

---

# Project Status

CipherDrop currently includes:

- Client-side AES-256-GCM encryption
- Web Crypto API integration
- Temporary secret storage
- Secret expiration
- Maximum view limits
- Burn-after-reading
- Password protection
- Management-token validation
- Secret management and deletion
- PostgreSQL persistence
- React frontend
- Spring Boot backend
- QR-code sharing
- Sensitive-data detection
- Security Advisor
- Frontend security scoring
- Automated frontend tests
- Backend tests
- Vite development proxy
- Vercel SPA configuration
- Docker backend configuration
- Cloud deployment support

---

# Repository

GitHub:

https://github.com/Strobes3003/cipherdrop
