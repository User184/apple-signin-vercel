import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
    console.log('Apple callback received');
    console.log('Method:', req.method);
    console.log('Body:', req.body);

    const PACKAGE_NAME = 'com.astrDevProd.astrology';
    const params = req.method === 'POST' ? req.body : req.query;

    try {
        // ОБЯЗАТЕЛЬНО: Если есть authorization code, обменяем его на токены
        if (params.code) {
            console.log('Authorization code received, exchanging for tokens...');

            try {
                const tokenResponse = await exchangeCodeForTokens(params.code);
                console.log('Token exchange successful:', {
                    hasAccessToken: !!tokenResponse.access_token,
                    hasRefreshToken: !!tokenResponse.refresh_token,
                    hasIdToken: !!tokenResponse.id_token
                });

                // КРИТИЧЕСКИ ВАЖНО: Добавляем полученные токены к параметрам
                if (tokenResponse.access_token) {
                    params.access_token = tokenResponse.access_token;
                    console.log('✅ Access token получен и добавлен');
                }
                if (tokenResponse.refresh_token) {
                    params.refresh_token = tokenResponse.refresh_token;
                    console.log('✅ Refresh token получен и добавлен');
                }
                if (tokenResponse.id_token) {
                    params.id_token = tokenResponse.id_token;
                }

            } catch (error) {
                console.error('❌ КРИТИЧЕСКАЯ ОШИБКА: Token exchange failed:', error);
                // НЕ ПРОДОЛЖАЕМ без токенов - это проблема!
                throw error;
            }
        }

        // Обрабатываем user данные
        if (params.user) {
            try {
                const userInfo = JSON.parse(params.user);
                console.log('Parsed user info:', userInfo);

                if (userInfo.sub) {
                    params.userIdentifier = userInfo.sub;
                }
                if (userInfo.email) {
                    params.email = userInfo.email;
                }
            } catch (e) {
                console.log('Failed to parse user JSON:', e);
            }
        }

        // Создаем intent URL для Android
        const intentUrl = `intent://callback?${new URLSearchParams(params).toString()}#Intent;package=${PACKAGE_NAME};scheme=signinwithapple;end`;

        console.log('Final params keys:', Object.keys(params));
        console.log('Redirecting to Android app...');

        res.redirect(307, intentUrl);

    } catch (error) {
        console.error('Error in callback processing:', error);

        // В случае ошибки все равно делаем redirect с базовыми параметрами
        const intentUrl = `intent://callback?${new URLSearchParams(params).toString()}#Intent;package=${PACKAGE_NAME};scheme=signinwithapple;end`;
        res.redirect(307, intentUrl);
    }
}

async function exchangeCodeForTokens(authorizationCode) {
    const APPLE_TEAM_ID = 'W6MB6STC78';
    const APPLE_KEY_ID = 'UKGR4F4DC6';
    const APPLE_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgJaaHhnn3JUop6ggY
MNrrsHTaO0e2OKL6vLABIErlAKugCgYIKoZIzj0DAQehRANCAARZXXT5DAgnpUhb
iODC/ZvmGzrYd4J0kexI/SSgdJLCqpuQlCOyW00mZHtvOXUqDSTzzNVxnxziNnSy
K3ZU4pgW
-----END PRIVATE KEY-----`;

    // Генерируем client_secret
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        iss: APPLE_TEAM_ID,
        iat: now,
        exp: now + 3600,
        aud: 'https://appleid.apple.com',
        sub: 'com.astrDevProd.astrology.signin',
    };

    const clientSecret = jwt.sign(payload, APPLE_PRIVATE_KEY, {
        algorithm: 'ES256',
        header: { kid: APPLE_KEY_ID, alg: 'ES256' }
    });

    // Обмениваем код на токены
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
        throw new Error(`Token exchange failed: ${response.status}`);
    }

    const tokenData = await response.json();
    console.log('Token exchange result keys:', Object.keys(tokenData));
    return tokenData;
}