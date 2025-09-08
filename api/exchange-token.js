import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const debugLogs = []; // Для сбора логов

    try {
        const { authorizationCode } = req.body;

        if (!authorizationCode) {
            return res.status(400).json({ error: 'Authorization code required' });
        }

        debugLogs.push('Exchanging authorization code for tokens...');
        console.log('Exchanging authorization code for tokens...');

        // Обменяем код на токены
        const result = await exchangeCodeForTokens(authorizationCode, debugLogs);

        debugLogs.push(`Token exchange successful: hasAccess=${!!result.access_token}, hasRefresh=${!!result.refresh_token}`);
        console.log(`Token exchange successful: hasAccess=${!!result.access_token}, hasRefresh=${!!result.refresh_token}`);

        return res.status(200).json({
            success: true,
            access_token: result.access_token,
            refresh_token: result.refresh_token,
            id_token: result.id_token,
            expires_in: result.expires_in,
            debug_logs: debugLogs // ← ЛОГИ ПРЯМО В ОТВЕТЕ
        });

    } catch (error) {
        debugLogs.push(`Error: ${error.message}`);
        console.error('Error exchanging tokens:', error);
        return res.status(500).json({
            success: false,
            error: 'Token exchange failed',
            details: error.message,
            debug_logs: debugLogs // ← ЛОГИ ДАЖЕ ПРИ ОШИБКЕ
        });
    }
}

async function exchangeCodeForTokens(authorizationCode, debugLogs) {
    const clientSecret = generateAppleClientSecret();

    debugLogs.push('Trying with main Bundle ID: com.astrDevProd.astrology');
    console.log('Trying to exchange token with client_id: com.astrDevProd.astrology');

    const response = await fetch('https://appleid.apple.com/auth/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            client_id: 'com.astrDevProd.astrology',
            client_secret: clientSecret,
            code: authorizationCode,
            grant_type: 'authorization_code',
        })
    });

    if (!response.ok) {
        const errorText = await response.text();
        debugLogs.push(`Failed with main Bundle ID: ${response.status} - ${errorText}`);
        console.error('Token exchange failed:', response.status, errorText);
        throw new Error(`Token exchange failed: ${response.status} - ${errorText}`);
    }

    debugLogs.push('✅ SUCCESS with main Bundle ID!');
    console.log('SUCCESS with main Bundle ID!');
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