# Passkey Login Demo

A passwordless login system built with WebAuthn passkeys.

**Live demo:** https://webauthentication-wj5b.onrender.com

> The free server sleeps when idle, so the first load may take about a minute.

## Features

- Sign up with username and password (password hashed with bcrypt)
- Register a passkey (Touch ID, Windows Hello, or phone)
- Log in with a passkey, no password typed
- Session cookies, stored in MongoDB, with log out
- Input checks: empty fields, short passwords, duplicate usernames

## Tech stack

Node.js, Express, MongoDB Atlas, @simplewebauthn/server, express-session, bcryptjs, deployed on Render.

## How passkey login works

1. The server sends a random challenge.
2. The user's device signs it with a private key that never leaves the device.
3. The server checks the signature with the saved public key.

## Run it locally

1. `npm install`
2. Create a `.env` file with `MONGODB_URI`, `SESSION_SECRET`, `RP_ID=localhost` and `ORIGIN=http://localhost:3000`
3. `node index.js`
4. Open http://localhost:3000

