CipherDrop — Complete Architecture Report

Team Technical Design Document — Architecture Frozen



This document describes the complete architecture agreed upon for CipherDrop. It should act as the shared technical reference for the team before implementation.



1\. Project Overview

What is CipherDrop?



CipherDrop is a secure, temporary secret-sharing platform.



A user can share sensitive information such as:



API keys

passwords

access tokens

database credentials

private configuration values

other confidential text



The important principle is:



The secret is encrypted in the user's browser before it is sent to the server.



The backend stores only encrypted data and controls whether that encrypted data may be accessed.



2\. Core Problem



Sensitive information is often shared through:



chat applications

email

plain text documents

screenshots

collaboration tools



Once sent, the sender often loses control over:



how long the information remains accessible

how many times it can be viewed

whether it requires a password

whether it should disappear after being read



CipherDrop addresses this by combining:



CLIENT-SIDE ENCRYPTION

&#x20;       +

SERVER-SIDE ACCESS POLICIES

&#x20;       +

TEMPORARY / LIMITED SECRET SHARING

3\. Core Architectural Idea



CipherDrop separates two responsibilities.



Confidentiality



Handled by the browser.



Plaintext

&#x20;   ↓

AES-GCM Encryption

&#x20;   ↓

Ciphertext

&#x20;   ↓

Server stores ciphertext



The backend never receives the AES encryption key.



Access Control



Handled by the Spring Boot backend.



The backend decides whether the encrypted content should be released.



It evaluates policies such as:



Is the secret expired?

Has it already been consumed?

Has the view limit been reached?

Is a password required?

Is the supplied password correct?



Therefore:



Browser

│

├── Protects the content

│

└── Decrypts the content









Backend

│

├── Stores encrypted content

│

└── Controls access to encrypted content



This is the central architectural identity of CipherDrop.



4\. High-Level System Architecture

&#x20;                        ┌─────────────────────┐

&#x20;                        │       USER          │

&#x20;                        └──────────┬──────────┘

&#x20;                                   │

&#x20;                                   ▼

&#x20;                        ┌─────────────────────┐

&#x20;                        │    React Frontend   │

&#x20;                        │                     │

&#x20;                        │ • UI                │

&#x20;                        │ • Encryption        │

&#x20;                        │ • Decryption        │

&#x20;                        │ • Security Advisor  │

&#x20;                        └──────────┬──────────┘

&#x20;                                   │

&#x20;                             HTTPS / REST

&#x20;                                   │

&#x20;                                   ▼

&#x20;                        ┌─────────────────────┐

&#x20;                        │   Spring Boot API   │

&#x20;                        │                     │

&#x20;                        │ • Secret Service    │

&#x20;                        │ • Policy Engine     │

&#x20;                        │ • Password Verify   │

&#x20;                        │ • Access Control    │

&#x20;                        └──────────┬──────────┘

&#x20;                                   │

&#x20;                                   ▼

&#x20;                        ┌─────────────────────┐

&#x20;                        │     PostgreSQL      │

&#x20;                        │                     │

&#x20;                        │ • Ciphertext        │

&#x20;                        │ • IV                │

&#x20;                        │ • Password Hash     │

&#x20;                        │ • Policies          │

&#x20;                        │ • Secret State      │

&#x20;                        └─────────────────────┘

5\. Encryption Architecture

Encryption algorithm



CipherDrop uses:



AES-GCM



through the browser's:



Web Crypto API



The browser generates:



Random AES-256 Key

&#x20;       +

Random IV



Then:



PLAINTEXT

&#x20;   │

&#x20;   ▼

AES-GCM

&#x20;   │

&#x20;   ├── AES Key

&#x20;   └── IV

&#x20;   │

&#x20;   ▼

CIPHERTEXT

Where does the AES key go?



The AES key is placed in the URL fragment.



Example:



https://cipherdrop.app/s/abc123#AES\_KEY



This URL contains two different pieces of information:



/s/abc123

&#x20;   │

&#x20;   └── Secret identifier

&#x20;       Sent to the server









\#AES\_KEY

&#x20;   │

&#x20;   └── Decryption key

&#x20;       Available to the browser

&#x20;       Not sent as part of the normal HTTP request



Therefore the database stores:



Ciphertext ✅

IV         ✅

Policies   ✅

AES Key    ❌

6\. Complete Secret Creation Lifecycle

Step 1 — User enters a secret



Example:



AWS\_SECRET\_ACCESS\_KEY=my-secret-value



The user may also choose:



Password protection: ON/OFF

Expiration: Optional

Burn after reading: ON/OFF

Maximum views: Optional

Step 2 — Sensitive data detection



The frontend analyzes the entered content.



Examples of detectable patterns:



API\_KEY

TOKEN

PASSWORD

DATABASE\_URL

PRIVATE\_KEY



The Security Advisor can recommend policies.



Example:



⚠ Sensitive credential detected





Recommended:

✓ Password protection

✓ Expire after 1 hour

✓ Burn after reading

✓ Maximum views: 1



The advisor recommends settings.



The user remains in control.



Step 3 — Browser encrypts the content

Plaintext

&#x20;   │

&#x20;   ▼

Generate random AES-256 key

&#x20;   │

&#x20;   ▼

Generate random IV

&#x20;   │

&#x20;   ▼

AES-GCM encryption

&#x20;   │

&#x20;   ▼

Ciphertext



The plaintext is not sent to the backend.



Step 4 — Backend receives encrypted data



The frontend sends:



{

&#x20; "encryptedContent": "base64-ciphertext",

&#x20; "iv": "base64-iv",

&#x20; "expiresAt": "2026-08-21T10:00:00Z",

&#x20; "burnAfterReading": true,

&#x20; "maxViews": 1,

&#x20; "password": "optional-password"

}



If a password exists:



Password

&#x20;   ↓

PasswordEncoder

&#x20;   ↓

Password Hash

&#x20;   ↓

Database



The actual password must not be stored.



Step 5 — Backend creates the secret



The backend generates:



Secret ID



and a separate:



Management Token



The database stores only a hash of the management token, not the raw token.



The creation response returns the raw management token once, because the client needs it for future management.



Step 6 — Frontend constructs the share URL



Example:



https://cipherdrop.app/s/abc123#AES\_KEY



Optionally, the creator can also receive a management URL:



/manage/abc123#MANAGEMENT\_TOKEN



The management token must never be included in the normal share link.



7\. Secret Access Lifecycle



When a recipient opens:



/s/abc123#AES\_KEY



React extracts:



Secret ID = abc123

AES Key = value after #



The frontend first checks the access state.



Then, only when the recipient intentionally unlocks/accesses the secret, the backend evaluates the full access policy.



8\. Policy Engine



The Policy Engine is responsible for answering:



Should this request receive the encrypted content?



It checks:



1\. Does the secret exist?

2\. Is the secret ACTIVE?

3\. Has it expired?

4\. Is a password required?

5\. Is the password correct?

6\. Has the view limit been reached?



Conceptually:



&#x20;                ACCESS REQUEST

&#x20;                       │

&#x20;                       ▼

&#x20;               ┌───────────────┐

&#x20;               │ POLICY ENGINE │

&#x20;               └───────┬───────┘

&#x20;                       │

&#x20;        ┌──────────────┼──────────────┐

&#x20;        ▼              ▼              ▼

&#x20;      Status       Password       View Limit

&#x20;        │              │              │

&#x20;        └──────────────┼──────────────┘

&#x20;                       │

&#x20;                       ▼

&#x20;                     ALLOW?

&#x20;                    /      \\

&#x20;                  YES       NO

&#x20;                   │         │

&#x20;                   ▼         ▼

&#x20;             Ciphertext     Deny

9\. Password Protection Model



CipherDrop uses password protection as an access-control layer.



The password is sent over HTTPS to the backend.



The backend:



Entered Password

&#x20;      │

&#x20;      ▼

PasswordEncoder.matches()

&#x20;      │

&#x20;      ├── Incorrect → DENY

&#x20;      │

&#x20;      └── Correct → Continue access



The backend stores only:



passwordHash



The password is not used as the AES encryption key in the current CipherDrop architecture.



Therefore CipherDrop's model is:



AES Key

&#x20;   ↓

Protects confidentiality









Password

&#x20;   ↓

Controls whether ciphertext is released

10\. Burn After Reading



If:



burnAfterReading = true



a successful access does:



Access allowed

&#x20;     ↓

View consumed

&#x20;     ↓

Ciphertext returned to successful request

&#x20;     ↓

Secret status → CONSUMED



Future requests receive:



CONSUMED



The successful recipient can still decrypt the ciphertext they already received.



The backend can later clear the stored ciphertext during cleanup if desired.



11\. Maximum View Limit



Example:



maxViews = 3

currentViews = 2



A successful access:



2 < 3

&#x20;  ↓

Allow

&#x20;  ↓

currentViews = 3



The next request:



3 >= 3

&#x20;  ↓

DENY

12\. Concurrency Requirement



This is important.



Two users must not both receive the final available view.



For example:



maxViews = 1

currentViews = 0



We want:



Request A

&#x20;   ↓

Consumes view

&#x20;   ↓

currentViews = 1

&#x20;   ↓

GRANTED









Request B

&#x20;   ↓

View limit reached

&#x20;   ↓

DENIED



The implementation of the access operation must therefore use a transaction and concurrency-safe database operation.



Conceptually:



BEGIN TRANSACTION





Find secret with appropriate locking / atomic update





Check policy





Increment currentViews





If burnAfterReading:

&#x20;   status = CONSUMED





COMMIT



The exact JPA locking strategy can be chosen during implementation, but this concurrency guarantee is part of the frozen architecture.



13\. Secret States



The main SecretStatus enum is:



ACTIVE

CONSUMED

DELETED

EXPIRED



Lifecycle:



&#x20;                ┌──────────┐

&#x20;                │  ACTIVE  │

&#x20;                └────┬─────┘

&#x20;                     │

&#x20;         ┌───────────┼────────────┐

&#x20;         ▼           ▼            ▼

&#x20;      EXPIRED     CONSUMED      DELETED



The view limit does not necessarily need a separate database status.



Instead:



currentViews >= maxViews



causes access to be denied with:



VIEW\_LIMIT\_REACHED

14\. Database Architecture

Main table: secrets



Recommended fields:



Field	Purpose

id	Unique secret identifier

encrypted\_content	AES-GCM encrypted data

iv	Initialization vector

password\_hash	Hash of optional password

management\_token\_hash	Hash of creator management token

expires\_at	Optional expiration time

burn\_after\_reading	Whether successful access consumes the secret

max\_views	Optional maximum number of accesses

current\_views	Number of successfully consumed accesses

status	ACTIVE / EXPIRED / CONSUMED / DELETED

created\_at	Creation timestamp

consumed\_at	Consumption timestamp if applicable



Important:



AES encryption key ❌ NOT STORED

Plaintext          ❌ NOT STORED

Raw password       ❌ NOT STORED

Raw management token ❌ NOT STORED

15\. Optional secret\_events Table



This is a lower-priority feature.



Possible structure:



secret\_events





id

secret\_id

event\_type

created\_at



Possible events:



CREATED

ACCESS\_GRANTED

PASSWORD\_FAILED

CONSUMED

EXPIRED

DELETED



This can support a security activity timeline later.



However:



Do not implement this before the core encrypted sharing flow works.



16\. Frozen REST API

A. Create Secret

POST /api/secrets



Request:



{

&#x20; "encryptedContent": "base64-ciphertext",

&#x20; "iv": "base64-iv",

&#x20; "expiresAt": "2026-08-21T10:00:00Z",

&#x20; "burnAfterReading": true,

&#x20; "maxViews": 1,

&#x20; "password": "optional-password"

}



Response:



201 Created

{

&#x20; "id": "abc123",

&#x20; "managementToken": "creator-management-token"

}



The frontend then constructs:



/s/abc123#AES\_KEY

B. Check Access State

GET /api/secrets/{id}



This endpoint does not return ciphertext.



Possible responses:



{

&#x20; "access": "READY"

}



or:



{

&#x20; "access": "PASSWORD\_REQUIRED"

}



Other unavailable states include:



EXPIRED

CONSUMED

VIEW\_LIMIT\_REACHED



A nonexistent secret returns:



404 Not Found

C. Access / Consume Secret

POST /api/secrets/{id}/access



For password-protected secrets:



{

&#x20; "password": "user-entered-password"

}



For secrets without passwords:



{}



This is the only endpoint that actually grants access and returns ciphertext.



Successful response:



{

&#x20; "access": "GRANTED",

&#x20; "encryptedContent": "base64-ciphertext",

&#x20; "iv": "base64-iv"

}



This endpoint:



checks the secret

checks status

checks expiration

verifies password

checks view limit

atomically consumes the view

consumes the secret if burn-after-reading is enabled

returns ciphertext and IV

D. Delete Secret

DELETE /api/secrets/{id}



The management token should be provided as a credential, for example:



Authorization: Bearer MANAGEMENT\_TOKEN



The backend verifies the token against:



management\_token\_hash



Then:



status = DELETED

17\. API Error Behavior



Recommended responses:



Situation	HTTP Status	Reason

Secret not found	404	NOT\_FOUND

Secret expired	410	EXPIRED

Secret consumed	410	CONSUMED

View limit reached	410	VIEW\_LIMIT\_REACHED

Wrong password	403	INVALID\_PASSWORD

Invalid management token	403	INVALID\_MANAGEMENT\_TOKEN



Example:



{

&#x20; "access": "DENIED",

&#x20; "reason": "EXPIRED"

}

18\. Spring Boot Internal Architecture



Recommended structure:



com.cipherdrop

│

├── controller

│   └── SecretController

│

├── service

│   └── SecretService

│

├── policy

│   └── SecretPolicyEngine

│

├── repository

│   └── SecretRepository

│

├── entity

│   └── Secret

│

├── dto

│   ├── CreateSecretRequest

│   ├── CreateSecretResponse

│   ├── SecretStatusResponse

│   ├── AccessSecretRequest

│   └── AccessSecretResponse

│

├── enums

│   └── SecretStatus

│

├── exception

│   ├── SecretNotFoundException

│   ├── SecretExpiredException

│   ├── SecretConsumedException

│   ├── InvalidPasswordException

│   └── ViewLimitReachedException

│

├── config

│   └── SecurityConfig

│

└── CipherDropApplication

19\. Responsibilities of Each Backend Layer

Controller



Responsible for:



Receive HTTP request

&#x20;       ↓

Validate request format

&#x20;       ↓

Call service

&#x20;       ↓

Return HTTP response



The controller should not contain business logic.



Service



SecretService is the main coordinator.



Example:



SecretController

&#x20;      ↓

SecretService

&#x20;      ↓

Policy Engine

&#x20;      ↓

Repository

&#x20;      ↓

PostgreSQL



The service coordinates:



creation

password hashing

secret retrieval

access transactions

consumption

deletion

Policy Engine



SecretPolicyEngine contains the access rules.



Conceptually:



validateAccess(secret, password)



It checks:



Status

Expiration

Password

View limit



This separation makes the policy-driven architecture explicit in the codebase.



Repository



Responsible only for database interaction.



Examples:



save()

findById()

delete/update operations



The repository does not decide whether access should be allowed.



Entity



Represents the PostgreSQL secrets table.



DTOs



DTOs define communication between:



React

&#x20; ↓

REST API

&#x20; ↓

Spring Boot



The frontend must not directly control internal database fields such as:



passwordHash

managementTokenHash

currentViews

status

createdAt

20\. Critical Access Transaction



The central backend operation is:



POST /api/secrets/{id}/access



Flow:



SecretController

&#x20;      │

&#x20;      ▼

SecretService.accessSecret()

&#x20;      │

&#x20;      ▼

Find secret safely

&#x20;      │

&#x20;      ▼

SecretPolicyEngine

&#x20;      │

&#x20;      ├── Status

&#x20;      ├── Expiration

&#x20;      ├── Password

&#x20;      └── View limit

&#x20;      │

&#x20;      ▼

Consume view

&#x20;      │

&#x20;      ▼

Burn after reading?

&#x20;      │

&#x20;      ├── Yes → CONSUMED

&#x20;      │

&#x20;      └── No

&#x20;      │

&#x20;      ▼

Commit transaction

&#x20;      │

&#x20;      ▼

Return ciphertext + IV



The operation must be transactional.



21\. React Frontend Architecture



Recommended structure:



src/

│

├── pages/

│   ├── HomePage.jsx

│   ├── CreateSecretPage.jsx

│   ├── SecretAccessPage.jsx

│   └── ManageSecretPage.jsx

│

├── components/

│   │

│   ├── layout/

│   │   ├── Navbar.jsx

│   │   └── Footer.jsx

│   │

│   ├── create/

│   │   ├── SecretEditor.jsx

│   │   ├── SecurityAdvisor.jsx

│   │   ├── SecurityScore.jsx

│   │   └── PolicyControls.jsx

│   │

│   ├── access/

│   │   ├── PasswordPrompt.jsx

│   │   ├── SecretViewer.jsx

│   │   └── SecretUnavailable.jsx

│   │

│   └── common/

│       ├── Button.jsx

│       └── Loading.jsx

│

├── services/

│   └── secretApi.js

│

└── utils/

&#x20;   ├── encryption.js

&#x20;   ├── sensitiveDetector.js

&#x20;   └── securityScore.js

22\. Frontend Pages

/



Home page.



Purpose:



explain CipherDrop

show security concept

provide CTA



Main action:



CREATE SECURE SHARE

/create



The main secret creation page.



Contains:



Secret Editor

&#x20;      +

Sensitive Data Detection

&#x20;      +

Security Advisor

&#x20;      +

Security Score

&#x20;      +

Policy Controls



Then:



Encrypt

&#x20;  ↓

POST /api/secrets

&#x20;  ↓

Receive ID

&#x20;  ↓

Generate share URL

/s/:id



The recipient access page.



Example:



/s/abc123#AES\_KEY



The page:



extracts the secret ID

extracts the AES key from the URL fragment

checks access state

requests password if necessary

calls the access endpoint

receives ciphertext and IV

decrypts locally

displays the plaintext

/manage/:id



Lower-priority creator management page.



Possible features:



Current status

Expiration information

Delete secret



This should only be implemented after the core flow works.



23\. Frontend Utility Architecture

encryption.js



Responsible for:



generateKey()

encryptSecret()

decryptSecret()



Uses:



Web Crypto API

AES-GCM

sensitiveDetector.js



Responsible for:



Input text

&#x20;   ↓

Pattern detection

&#x20;   ↓

Sensitive categories



Possible output:



\[

&#x20; {

&#x20;   type: "API\_KEY",

&#x20;   severity: "HIGH"

&#x20; }

]

securityScore.js



Calculates a score based on:



Detected sensitivity

&#x20;       +

Password enabled

&#x20;       +

Expiration

&#x20;       +

Burn after reading

&#x20;       +

Maximum views



Output:



0 ─────────────────────── 100

Low Security        High Security

24\. Complete End-to-End Flow

CREATOR

Send ciphertext + IV to backend

────────────────────────────────

&#x20;  │

&#x20;  ▼

SPRING BOOT

&#x20;  │

&#x20;  ├── Hash password

&#x20;  ├── Hash management token

&#x20;  ├── Store policies

&#x20;  └── Generate secret ID

&#x20;  │

&#x20;  ▼

POSTGRESQL

&#x20;  │

&#x20;  ▼

Return secret ID + management token

&#x20;  │

&#x20;  ▼

React constructs:

&#x20;  │

&#x20;  ▼

/s/{id}#AES\_KEY

&#x20;  │

&#x20;  │

&#x20;  ▼

RECIPIENT

&#x20;  │

&#x20;  ▼

Open share link

&#x20;  │

&#x20;  ▼

GET secret access state

&#x20;  │

&#x20;  ▼

Password required?

&#x20;  │

&#x20;  ├── Yes → Show password form

&#x20;  │

&#x20;  └── No → Ready to unlock

&#x20;             │

&#x20;             ▼

POST /api/secrets/{id}/access

&#x20;             │

&#x20;             ▼

POLICY ENGINE

&#x20;             │

&#x20;      ┌──────┼─────────┐

&#x20;      ▼      ▼         ▼

&#x20;   Status Password  View Limit

&#x20;      │      │         │

&#x20;      └──────┼─────────┘

&#x20;             │

&#x20;             ▼

&#x20;           ALLOW?

&#x20;          /      \\

&#x20;        YES       NO

&#x20;         │         │

&#x20;         ▼         ▼

&#x20;Ciphertext + IV   DENY

&#x20;         │

&#x20;         ▼

Browser reads AES key

from URL fragment

&#x20;         │

&#x20;         ▼

AES-GCM decryption

&#x20;         │

&#x20;         ▼

DISPLAY PLAINTEXT

25\. Team Split

Person 1 — Backend Core



Responsible for:



Spring Boot setup

PostgreSQL

Secret entity

Repository

DTOs

Create Secret API

Database configuration



Primary endpoint:



POST /api/secrets

Person 2 — Backend Policy \& Security



Responsible for:



SecretPolicyEngine

Access flow

Password verification

Expiration

Burn after reading

View limits

Concurrency handling

Management token validation

Delete endpoint



Primary endpoints:



GET    /api/secrets/{id}

POST   /api/secrets/{id}/access

DELETE /api/secrets/{id}

Person 3 — Frontend UI



Responsible for:



React setup

Routing

Home page

Create page

Secret editor

Policy controls

Access page UI

API integration layer

Person 4 — Frontend Security \& Intelligence



Responsible for:



AES-GCM encryption

AES-GCM decryption

Web Crypto API

URL fragment key handling

Sensitive data detection

Security Advisor

Security Score



Expose clean functions such as:



encryptSecret()

decryptSecret()

detectSensitiveData()

calculateSecurityScore()

26\. Repository Structure



Use a monorepo:



cipherdrop/

│

├── backend/

│

├── frontend/

│

├── docs/

│   └── architecture.md

│

├── README.md

└── .gitignore

27\. Git Workflow



Main branches:



main

│

├── backend-core

├── backend-policy

├── frontend-ui

└── frontend-security



Recommended workflow:



Feature branch

&#x20;     ↓

Code

&#x20;     ↓

Commit

&#x20;     ↓

Push

&#x20;     ↓

Pull Request

&#x20;     ↓

Quick review

&#x20;     ↓

Merge into main



Important rule:



Nobody pushes directly to main.



Also:



Do not keep branches unmerged until the final hour.



Merge independently working components regularly.



28\. Development Priority

Level 1 — Core MVP 🔴



This must work first:



1\. React setup

2\. Spring Boot setup

3\. PostgreSQL

4\. AES-GCM encryption

5\. Create secret

6\. Store ciphertext

7\. Generate share link

8\. Retrieve ciphertext

9\. Decrypt successfully

10\. Display original secret



The first milestone is:



ENTER TEXT

&#x20;   ↓

ENCRYPT LOCALLY

&#x20;   ↓

STORE CIPHERTEXT

&#x20;   ↓

GENERATE LINK

&#x20;   ↓

OPEN LINK

&#x20;   ↓

RETRIEVE CIPHERTEXT

&#x20;   ↓

DECRYPT LOCALLY

&#x20;   ↓

DISPLAY ORIGINAL TEXT



Do not start adding many extra features before this works end-to-end.



Level 2 — Security Policies 🟠

Password protection

Expiration

Burn after reading

Maximum views

Level 3 — Differentiators 🟡

Sensitive-data detection

Security Advisor

Security Score

Level 4 — Polish 🟢

Management page

Secret event history

Animations

Better error screens

Deployment

README/demo improvements

29\. Final Architecture Decisions



These decisions are considered frozen unless the entire team agrees to change them.



Frontend

React



Handles:



Encryption

Decryption

URL key handling

Sensitive-data detection

Security recommendations

UI

Backend

Spring Boot



Handles:



Ciphertext storage

Password hashing

Management-token verification

Policy enforcement

Secret lifecycle

Access control

Database

PostgreSQL



Stores:



Ciphertext

IV

Password hash

Management token hash

Policies

Lifecycle state

Encryption

Web Crypto API

AES-GCM

Random 256-bit AES key

Key storage

URL fragment





/s/{id}#AES\_KEY

Core architectural principle

CLIENT-SIDE CONFIDENTIALITY

&#x20;           +

SERVER-SIDE POLICY ENFORCEMENT

&#x20;           +

SECURITY ADVISOR

30\. Final Summary



CipherDrop is not simply a text-sharing application with encryption added to it.



Its architecture deliberately separates:



WHO CAN READ THE DATA?

&#x20;           ↓

Backend Policy Engine









CAN THE SERVER READ THE DATA?

&#x20;           ↓

No — it stores ciphertext only



The final system can be summarized as:



&#x20;                  CIPHERDROP





&#x20;       ┌─────────────────────────────┐

&#x20;       │         FRONTEND            │

&#x20;       │                             │

&#x20;       │  Encrypt → Share → Decrypt  │

&#x20;       │                             │

&#x20;       └──────────────┬──────────────┘

&#x20;                      │

&#x20;                 Ciphertext

&#x20;                      │

&#x20;                      ▼

&#x20;       ┌─────────────────────────────┐

&#x20;       │       SPRING BOOT           │

&#x20;       │                             │

&#x20;       │       POLICY ENGINE         │

&#x20;       │                             │

&#x20;       │ Password • Expiry • Views   │

&#x20;       │ Burn After Reading          │

&#x20;       └──────────────┬──────────────┘

&#x20;                      │

&#x20;                      ▼

&#x20;       ┌─────────────────────────────┐

&#x20;       │         POSTGRESQL          │

&#x20;       │                             │

&#x20;       │ Ciphertext • IV • Policies  │

&#x20;       │ Password Hash • State       │

&#x20;       └─────────────────────────────┘

CipherDrop Architecture: FROZEN ✅



