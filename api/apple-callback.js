import jwt from 'jsonwebtoken';

/**
 * Обрабатывает callback от Apple Sign In (для Android веб-авторизации)
 * Обменивает authorization code на токены и перенаправляет в Android приложение
 */
export default async function handler(req, res) {
    const PACKAGE_NAME = 'com.astrDevProd.astrology';
    const params = req.method === 'POST' ? req.body : req.query;

    try {
        // Если есть authorization code, обменяем его на токены
        if (params.code) {
            const tokenResponse = await exchangeCodeForTokens(params.code);

            // Добавляем полученные токены к параметрам для передачи в приложение
            if (tokenResponse.access_token) {
                params.access_token = tokenResponse.access_token;
            }
            if (tokenResponse.refresh_token) {
                params.refresh_token = tokenResponse.refresh_token;
            }
            if (tokenResponse.id_token) {
                params.id_token = tokenResponse.id_token;
            }
        }

        // Обрабатываем данные пользователя
        if (params.user) {
            try {
                const userInfo = JSON.parse(params.user);
                if (userInfo.sub) {
                    params.userIdentifier = userInfo.sub;
                }
                if (userInfo.email) {
                    params.email = userInfo.email;
                }
            } catch (e) {
                // Игнорируем ошибки парсинга user данных
            }
        }

        // Создаем intent URL для Android приложения
        const intentUrl = `intent://callback?${new URLSearchParams(params).toString()}#Intent;package=${PACKAGE_NAME};scheme=signinwithapple;end`;

        res.redirect(307, intentUrl);

    } catch (error) {
        // В случае ошибки все равно делаем redirect с базовыми параметрами
        const intentUrl = `intent://callback?${new URLSearchParams(params).toString()}#Intent;package=${PACKAGE_NAME};scheme=signinwithapple;end`;
        res.redirect(307, intentUrl);
    }
}

/**
 * Обменивает authorization code на токены
 */
async function exchangeCodeForTokens(authorizationCode) {
    const clientSecret = generateAppleClientSecret();

    const response = await fetch('https://appleid.apple.com/auth/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            client_id: 'com.astrDevProd.astrology',  // Bundle ID для токенов
            client_secret: clientSecret,
            code: authorizationCode,
            grant_type: 'authorization_code',
        })
    });

    if (!response.ok) {
        throw new Error(`Token exchange failed: ${response.status}`);
    }

    return await response.json();
}

/**
 * Генерирует JWT client_secret для Apple API
 */
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
        header: { kid: APPLE_KEY_ID, alg: 'ES256' }
    });
}