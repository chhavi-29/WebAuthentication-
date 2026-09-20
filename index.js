const express = require('express');
const crypto = require("node:crypto");
const {generateRegistrationOptions ,
    verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse
} = require('@simplewebauthn/server');

if (!globalThis.crypto) {
    globalThis.crypto = crypto;
}

const app = express();
const port = 3000;


app.use(express.static('./public'));
app.use(express.json());

// states
const userStore = {};

const challengeStore = {};


app.post('/register', (req, res) => {

    const { username, password } = req.body;
    const id = `user_${Date.now()}`;
    const user= {
        id,
        username,
        password

    }
    userStore[id] = user;

    console.log(` registered successfull`,userStore[id])

    return res.json({id})

})



app.post('/register-challenge', async(req, res) => {
    const {userId} = req.body;
  
    if (!userId || !userStore[userId]) {
        return res.status(404).json({ error: 'Invalid user ID' });
    }

    const user = userStore[userId];

    const challengePayload =  await generateRegistrationOptions({
        rpName: 'My localhost',
        rpID: 'localhost',
        userName: user.username,
                timeout: 30_000,


    })
    challengeStore[userId] = challengePayload.challenge;
    return res.json( {options : challengePayload });




})


app.post('/register-verify', async (req, res) => {
    const { userId, cred }  = req.body
    
    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })

    const user = userStore[userId]
    const challenge = challengeStore[userId]

    const verificationResult = await verifyRegistrationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        response: cred,
    })

    if (!verificationResult.verified) return res.json({ error: 'could not verify' });
    userStore[userId].passkey = verificationResult.registrationInfo.credential

    return res.json({ verified: true })

})


app.post('/login-challenge', async (req, res) => {
    const { userId } = req.body
    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })
    
    const opts = await generateAuthenticationOptions({
        rpID: 'localhost',
    })

    challengeStore[userId] = opts.challenge

    return res.json({ options: opts })
})

app.post('/login-verify', async (req, res) => {
    const { userId, cred }  = req.body

    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })
    const user = userStore[userId]
    const challenge = challengeStore[userId]

    const result = await verifyAuthenticationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        response: cred,
        credential: user.passkey
    })

    if (!result.verified) return res.json({ error: 'something went wrong' })
    
    // Login the user: Session, Cookies, JWT
    return res.json({ success: true, userId })
})



app.listen(port, () => console.log(`Server started on port ${port}`));