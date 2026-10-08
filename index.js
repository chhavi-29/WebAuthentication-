require('dotenv').config();

const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const express = require('express');
const crypto = require("node:crypto");
const { MongoClient } = require('mongodb');
const {generateRegistrationOptions ,
    verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse
} = require('@simplewebauthn/server');

if (!globalThis.crypto) {
    globalThis.crypto = crypto;
}

// --- MongoDB connection ---
const client = new MongoClient(process.env.MONGODB_URI);
client.connect()
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection failed:', err.message));

const db = client.db('passkeyapp');
const users = db.collection('users');

// --- Settings (from .env on your laptop, from the host's settings when live) ---
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || 'http://localhost:3000';

const app = express();
const port = process.env.PORT || 3000;


app.use(express.static('./public'));
app.use(express.json());

app.set('trust proxy', 1);

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        dbName: 'passkeyapp',
        ttl: 60 * 30
    }),
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: 1000 * 60 * 30
    }
}));

// Challenges are short-lived, so memory is fine for now
const challengeStore = {};


// ---------- Sign-up ----------
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    const existing = await users.findOne({ username });
    if (existing) {
        return res.status(409).json({ error: 'Username already taken' });
    }

    const id = `user_${Date.now()}`;
    const passwordHash = await bcrypt.hash(password, 10);

    await users.insertOne({ id, username, passwordHash });

    req.session.userId = id

    console.log('registered', id, username);
    return res.json({ id });
})


// ---------- Register a passkey ----------
app.post('/register-challenge', async (req, res) => {
    const userId = req.session.userId;

    const user = userId ? await users.findOne({ id: userId }) : null;
    if (!user) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    const challengePayload = await generateRegistrationOptions({
        rpName: 'My localhost',
        rpID: RP_ID,
        userName: user.username,
        timeout: 30_000,
    })
    challengeStore[userId] = challengePayload.challenge;
    return res.json({ options: challengePayload });
})


app.post('/register-verify', async (req, res) => {
    const { cred } = req.body
    const userId = req.session.userId

    const user = userId ? await users.findOne({ id: userId }) : null
    if (!user) return res.status(401).json({ error: 'Not logged in' })

    const challenge = challengeStore[userId]

    let verificationResult
    try {
        verificationResult = await verifyRegistrationResponse({
            expectedChallenge: challenge,
            expectedOrigin: ORIGIN,
            expectedRPID: RP_ID,
            response: cred,
        })
    } catch (error) {
        console.error(error)
        return res.status(400).json({ error: 'could not verify' })
    }

    if (!verificationResult.verified) return res.json({ error: 'could not verify' })

    const credential = verificationResult.registrationInfo.credential

    await users.updateOne(
        { id: userId },
        {
            $set: {
                passkey: {
                    id: credential.id,
                    publicKey: Buffer.from(credential.publicKey).toString('base64'),
                    counter: credential.counter,
                    transports: credential.transports
                }
            }
        }
    )

    delete challengeStore[userId]

    return res.json({ verified: true })
})


// ---------- Log in with a passkey ----------
app.post('/login-challenge', async (req, res) => {
    const { username } = req.body

    const user = await users.findOne({ username })
    if (!user || !user.passkey) {
        return res.status(404).json({ error: 'user not found or no passkey registered' })
    }

    const opts = await generateAuthenticationOptions({
        rpID: RP_ID,
    })

    challengeStore[user.id] = opts.challenge

    return res.json({ options: opts, userId: user.id })
})


app.post('/login-verify', async (req, res) => {
    const { userId, cred } = req.body

    const user = await users.findOne({ id: userId })
    if (!user || !user.passkey) {
        return res.status(404).json({ error: 'user not found!' })
    }

    const challenge = challengeStore[userId]
    if (!challenge) {
        return res.status(400).json({ error: 'No login in progress' })
    }

    let result
    try {
        result = await verifyAuthenticationResponse({
            expectedChallenge: challenge,
            expectedOrigin: ORIGIN,
            expectedRPID: RP_ID,
            response: cred,
            credential: {
                id: user.passkey.id,
                publicKey: new Uint8Array(Buffer.from(user.passkey.publicKey, 'base64')),
                counter: user.passkey.counter,
                transports: user.passkey.transports
            }
        })
    } catch (error) {
        console.error(error)
        return res.status(400).json({ error: 'Passkey verification failed' })
    }

    delete challengeStore[userId]

    if (!result.verified) return res.status(401).json({ error: 'Login failed' })

    await users.updateOne(
        { id: userId },
        { $set: { 'passkey.counter': result.authenticationInfo.newCounter } }
    )

    req.session.userId = userId
    return res.json({ success: true, userId })
})


// ---------- Who am I / log out ----------
app.get('/me', async (req, res) => {
    const user = await users.findOne({ id: req.session.userId });
    if (!user) return res.status(401).json({ error: 'Not logged in' });
    return res.json({ id: user.id, username: user.username });
})


app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid')
        res.json({ success: true })
    })
})


app.listen(port, () => console.log(`Server started on port ${port}`));