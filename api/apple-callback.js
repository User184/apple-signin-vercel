// api/apple-callback.js
import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
    console.log('Apple callback received');
    console.log('Method:', req.method);
    console.log('Body:', req.body);

    const PACKAGE_NAME = 'com.astrDevProd.astrology';
    const params = req.method === 'POST' ? req.body : req.query;

    try {
        // Если есть authorization code, обменяем его на access token
        if (params.code) {
            console.log('Authorization code received, exchanging for tokens...');

            const tokenResponse = await exchangeCodeForTokens(params.code);

            if (tokenResponse.access_token) {
                // Добавляем access_token к параметрам
                params.access_token = tokenResponse.access_token;
                params.refresh_token = tokenResponse.refresh_token;
                console.log('Tokens obtained successfully');
            }
        }

        // Обрабатываем user данные
        if (params.user) {
            try {
                const userInfo = JSON.parse(params.user);
                console.log('Parsed user info:', userInfo);

                if (userInfo.sub) {
                    params.userIdentifier = userInfo.sub;
                    console.log('Found userIdentifier:', userInfo.sub);
                }

                if (userInfo.email) {
                    params.email = userInfo.email;
                    console.log('Found email:', userInfo.email);
                }
            } catch (e) {
                console.log('Failed to parse user JSON:', e);
            }
        }

        console.log('Final params to send:', Object.keys(params));

        const intentUrl = `intent://callback?${new URLSearchParams(params).toString()}#Intent;package=${PACKAGE_NAME};scheme=signinwithapple;end`;

        console.log('Redirecting to:', intentUrl);
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
    console.log('Token exchange successful');
    return tokenData;
}