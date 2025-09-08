import jwt from 'jsonwebtoken';

/**
 * Отзывает Apple токены (access_token или refresh_token)
 * Автоматически определяет правильный client_id из identity token
 */
export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { authorizationCode, identityToken, refreshToken, accessToken } = req.body;

        // Определяем client_id из identity token (iOS: Bundle ID, Android: Service ID)
        let detectedClientId = null;
        if (identityToken) {
            try {
                const payload = JSON.parse(atob(identityToken.split('.')[1]));
                detectedClientId = payload.aud; // "aud" содержит client_id для которого выдан токен
            } catch (error) {
                // Игнорируем ошибки декодирования
            }
        }

        // Если нет готовых токенов, пробуем обменять authorization code
        let actualRefreshToken = refreshToken;
        let actualAccessToken = accessToken;

        if (authorizationCode && !refreshToken && !accessToken) {
            try {
                const tokenData = await exchangeCodeForTokens(authorizationCode);
                actualRefreshToken = tokenData.refresh_token;
                actualAccessToken = tokenData.access_token;
            } catch (error) {
                // Игнорируем ошибки обмена
            }
        }

        // Выбираем токен для отзыва (приоритет: refresh_token > access_token)
        const tokenToRevoke = actualRefreshToken || actualAccessToken;
        const tokenType = actualRefreshToken ? 'refresh_token' : 'access_token';

        if (!tokenToRevoke) {
            return res.status(400).json({
                error: 'No valid token found for revocation'
            });
        }

        // Отзываем токен с правильным client_id
        const revokeResult = await attemptTokenRevocation(tokenToRevoke, tokenType, detectedClientId);

        if (revokeResult.success) {
            return res.status(200).json({
                success: true,
                message: 'Token revoked successfully',
                revokedTokenType: tokenType,
                usedClientId: revokeResult.clientId
            });
        } else {
            return res.status(400).json({
                success: false,
                error: 'Failed to revoke token'
            });
        }

    } catch (error) {
        return res.status(500).json({
            success: false,
            error: 'Internal server error',
            details: error.message
        });
    }
}

/**
 * Пробует отозвать токен с разными client_id до успеха
 */
async function attemptTokenRevocation(token, tokenType, detectedClientId) {
    // Формируем список client_id для попытки (в порядке приоритета)
    const clientIds = [];

    // Первым пробуем определенный из токена
    if (detectedClientId) {
        clientIds.push(detectedClientId);
    }

    // Добавляем остальные варианты
    if (!detectedClientId || detectedClientId !== 'com.astrDevProd.astrology') {
        clientIds.push('com.astrDevProd.astrology');
    }
    if (!detectedClientId || detectedClientId !== 'com.astrDevProd.astrology.signin') {
        clientIds.push('com.astrDevProd.astrology.signin');
    }

    // Пробуем отозвать с каждым client_id
    for (const clientId of clientIds) {
        try {
            const clientSecret = generateAppleClientSecret(clientId);
            const response = await fetch('https://appleid.apple.com/auth/revoke', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    client_id: clientId,
                    client_secret: clientSecret,
                    token: token,
                    token_type_hint: tokenType
                })
            });

            if (response.status === 200) {
                return { success: true, clientId: clientId };
            }
        } catch (error) {
            // Игнорируем ошибки и пробуем следующий client_id
        }
    }

    return { success: false };
}

/**
 * Обменивает authorization code на токены (fallback функция)
 */
async function exchangeCodeForTokens(authorizationCode) {
    // Пробуем сначала с Bundle ID, затем с Service ID
    try {
        const clientSecret = generateAppleClientSecret('com.astrDevProd.astrology');
        return await attemptTokenExchange(authorizationCode, 'com.astrDevProd.astrology', clientSecret);
    } catch (error) {
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