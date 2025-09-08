import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { authorizationCode } = req.body;

        if (!authorizationCode) {
            return res.status(400).json({ error: 'Authorization code required' });
        }

        console.log('Exchanging authorization code for tokens...');

        // Обменяем код на токены
        const tokenData = await exchangeCodeForTokens(authorizationCode);

        console.log('Token exchange successful:', {
            hasAccessToken: !!tokenData.access_token,
            hasRefreshToken: !!tokenData.refresh_token
        });

        return res.status(200).json({
            success: true,
            access_token: tokenData.access_token,
            refresh_token: tokenData.refresh_token,
            id_token: tokenData.id_token,
            expires_in: tokenData.expires_in
        });

    } catch (error) {
        console.error('Error exchanging tokens:', error);
        return res.status(500).json({
            success: false,
            error: 'Token exchange failed',
            details: error.message
        });
    }
}

async function exchangeCodeForTokens(authorizationCode) {
    const clientSecret = generateAppleClientSecret();

    const response = await fetch('https://appleid.apple.com/auth/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            client_id: 'com.astrDevProd.astrology.signin',
            client_secret: clientSecret,
            code: authorizationCode,
            grant_type: 'authorization_code',
        })
    });

    if (!response.ok) {
        const errorText = await response.text();
        console.error('Token exchange failed:', response.status, errorText);
        throw new Error(`Token exchange failed: ${response.status} - ${errorText}`);
    }

    return await response.json();
}

function generateAppleClientSecret() {
    const APPLE_TEAM_ID = 'W6MB6STC78';
    const APPLE_KEY_ID = 'UKGR4F4DC6';
    const APPLE_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgJaaHhnn3JUop6ggY
MNrrsHTaO0e2OKL6vLABIErlAKugCgYIKoZIzj0DAQehRANCAARZXXT5DAgnpUhb
iODC/ZvmGzrYd4J0kexI/SSgdJLCqpuQlCOyW00mZHtvOXUqDSTzzNVxnxziNnSy
K3ZU4pgW
-----END PRIVATE KEY-----`;

    const now = Math.floor(Date.now() / 1000);

    const payload = {
        iss: APPLE_TEAM_ID,
        iat: now,
        exp: now + 3600,
        aud: 'https://appleid.apple.com',
        sub: 'com.astrDevProd.astrology',
    };

    return jwt.sign(payload, APPLE_PRIVATE_KEY, {
        algorithm: 'ES256',
        header: {
            kid: APPLE_KEY_ID,
            alg: 'ES256'
        }
    });
}