import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { authorizationCode, identityToken, refreshToken, accessToken } = req.body;

        console.log('Received tokens:', {
            hasAuthCode: !!authorizationCode,
            hasIdentityToken: !!identityToken,
            hasRefreshToken: !!refreshToken,
            hasAccessToken: !!accessToken
        });

        // Определяем client_id из токена (если есть)
        let detectedClientId = null;
        if (identityToken) {
            try {
                const payload = JSON.parse(atob(identityToken.split('.')[1]));
                detectedClientId = payload.aud;
                console.log('Detected client_id from identity token:', detectedClientId);
            } catch (error) {
                console.log('Failed to decode identity token:', error.message);
            }
        }

        // Если есть authorizationCode, сначала обменяем его на токены
        let actualRefreshToken = refreshToken;
        let actualAccessToken = accessToken;

        if (authorizationCode && !refreshToken && !accessToken) {
            console.log('Exchanging authorization code for tokens...');
            try {
                const tokenData = await exchangeCodeForTokens(authorizationCode);
                actualRefreshToken = tokenData.refresh_token;
                actualAccessToken = tokenData.access_token;
                console.log('Got tokens from code exchange');
            } catch (error) {
                console.error('Failed to exchange code:', error.message);
            }
        }

        // Определяем токен для отзыва (приоритет: refresh_token > access_token)
        const tokenToRevoke = actualRefreshToken || actualAccessToken;
        const tokenType = actualRefreshToken ? 'refresh_token' : 'access_token';

        if (!tokenToRevoke) {
            return res.status(400).json({
                error: 'No valid token found for revocation'
            });
        }

        console.log(`Attempting to revoke ${tokenType} with client_id: ${detectedClientId || 'auto-detect'}`);

        // Пробуем отозвать с правильным client_id
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
                error: 'Failed to revoke token',
                details: revokeResult.error
            });
        }

    } catch (error) {
        console.error('Error in revoke handler:', error);
        return res.status(500).json({
            success: false,
            error: 'Internal server error',
            details: error.message
        });
    }
}

async function attemptTokenRevocation(token, tokenType, detectedClientId) {
    // Список client_id для попытки (в порядке приоритета)
    const clientIds = [];

    if (detectedClientId) {
        clientIds.push(detectedClientId);
    }

    // Добавляем оба варианта если не определили из токена
    if (!detectedClientId || detectedClientId !== 'com.astrDevProd.astrology') {
        clientIds.push('com.astrDevProd.astrology');
    }
    if (!detectedClientId || detectedClientId !== 'com.astrDevProd.astrology.signin') {
        clientIds.push('com.astrDevProd.astrology.signin');
    }

    for (const clientId of clientIds) {
        try {
            console.log(`Trying to revoke with client_id: ${clientId}`);

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

            console.log(`Revoke response for ${clientId}: ${response.status}`);

            if (response.status === 200) {
                console.log(`✅ Successfully revoked with ${clientId}`);
                return { success: true, clientId: clientId };
            }

            const errorText = await response.text();
            console.log(`❌ Failed with ${clientId}: ${response.status} - ${errorText}`);
        } catch (error) {
            console.error(`Error with ${clientId}:`, error.message);
        }
    }

    return {
        success: false,
        error: `Failed to revoke with all client_ids: ${clientIds.join(', ')}`
    };
}

async function exchangeCodeForTokens(authorizationCode) {
    // Используем ту же логику что и в exchange-token.js
    try {
        const clientSecret = generateAppleClientSecret('com.astrDevProd.astrology');
        return await attemptTokenExchange(authorizationCode, 'com.astrDevProd.astrology', clientSecret);
    } catch (error) {
        const clientSecret = generateAppleClientSecret('com.astrDevProd.astrology.signin');
        return await attemptTokenExchange(authorizationCode, 'com.astrDevProd.astrology.signin', clientSecret);
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
        sub: clientId, // Используем правильный client_id
    };

    return jwt.sign(payload, APPLE_PRIVATE_KEY, {
        algorithm: 'ES256',
        header: {
            kid: APPLE_KEY_ID,
            alg: 'ES256'
        }
    });
}