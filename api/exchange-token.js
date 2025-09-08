import jwt from 'jsonwebtoken';

/**
 * Обменивает authorization code на access_token и refresh_token
 * Автоматически определяет правильный client_id (iOS: Bundle ID, Android: Service ID)
 */
export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { authorizationCode } = req.body;

        if (!authorizationCode) {
            return res.status(400).json({ error: 'Authorization code required' });
        }

        // Обмениваем код на токены с автоопределением client_id
        const tokenData = await exchangeCodeForTokens(authorizationCode);

        return res.status(200).json({
            success: true,
            access_token: tokenData.access_token,
            refresh_token: tokenData.refresh_token,
            id_token: tokenData.id_token,
            expires_in: tokenData.expires_in
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            error: 'Token exchange failed',
            details: error.message
        });
    }
}

/**
 * Пробует обменять authorization code сначала с Bundle ID (iOS), затем с Service ID (Android)
 */
async function exchangeCodeForTokens(authorizationCode) {
    // Сначала пробуем с Bundle ID для iOS
    try {
        const clientSecret = generateAppleClientSecret('com.astrDevProd.astrology');
        return await attemptTokenExchange(authorizationCode, 'com.astrDevProd.astrology', clientSecret);
    } catch (error) {
        // Если не сработало, пробуем с Service ID для Android
        const clientSecret = generateAppleClientSecret('com.astrDevProd.astrology.signin');
        return await attemptTokenExchange(authorizationCode, 'com.astrDevProd.astrology.signin', clientSecret);
    }
}

/**
 * Выполняет обмен authorization code на токены
 */
async function attemptTokenExchange(authorizationCode, clientId, clientSecret) {
    const response = await fetch('https://appleid.apple.com/auth/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            client_id: clientId,
            client_secret: clientSecret,
            code: authorizationCode,
            grant_type: 'authorization_code',
        })
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`${response.status} - ${errorText}`);
    }

    return await response.json();
}

/**
 * Генерирует JWT client_secret для Apple API
 */
function generateAppleClientSecret(clientId) {
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
        iss: APPLE_TEAM_ID,           // Team ID
        iat: now,                     // Время создания
        exp: now + 3600,              // Время истечения (1 час)
        aud: 'https://appleid.apple.com',
        sub: clientId,                // client_id (Bundle ID или Service ID)
    };

    return jwt.sign(payload, APPLE_PRIVATE_KEY, {
        algorithm: 'ES256',
        header: {
            kid: APPLE_KEY_ID,
            alg: 'ES256'
        }
    });
}