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
    // Сначала пробуем с основным Bundle ID (для iOS)
    debugLogs.push('Пробуем с Bundle ID для iOS: com.astrDevProd.astrology');

    try {
        const clientSecret = generateAppleClientSecret('com.astrDevProd.astrology');
        const result = await attemptTokenExchange(authorizationCode, 'com.astrDevProd.astrology', clientSecret);
        debugLogs.push('✅ SUCCESS с Bundle ID (iOS авторизация)');
        return result;
    } catch (error) {
        debugLogs.push(`Bundle ID не сработал: ${error.message}`);

        // Если не сработало, пробуем с Service ID (для Android)
        debugLogs.push('Пробуем с Service ID для Android: com.astrDevProd.astrology.signin');

        try {
            const clientSecret = generateAppleClientSecret('com.astrDevProd.astrology.signin');
            const result = await attemptTokenExchange(authorizationCode, 'com.astrDevProd.astrology.signin', clientSecret);
            debugLogs.push('✅ SUCCESS с Service ID (Android авторизация)');
            return result;
        } catch (error2) {
            debugLogs.push(`Service ID тоже не сработал: ${error2.message}`);
            throw new Error(`Оба варианта не сработали. Bundle ID: ${error.message}, Service ID: ${error2.message}`);
        }
    }
}

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
        iss: APPLE_TEAM_ID,
        iat: now,
        exp: now + 3600,
        aud: 'https://appleid.apple.com',
        sub: clientId, // Используем переданный client_id
    };

    return jwt.sign(payload, APPLE_PRIVATE_KEY, {
        algorithm: 'ES256',
        header: {
            kid: APPLE_KEY_ID,
            alg: 'ES256'
        }
    });
}