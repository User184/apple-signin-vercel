import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { authorizationCode, identityToken, refreshToken } = req.body;

        console.log('Received tokens:', {
            hasAuthCode: !!authorizationCode,
            hasIdentityToken: !!identityToken,
            hasRefreshToken: !!refreshToken
        });

        // Если есть authorizationCode, сначала обменяем его на токены
        let actualRefreshToken = refreshToken;

        if (authorizationCode && !refreshToken) {
            console.log('Exchanging authorization code for tokens...');
            try {
                const tokenData = await exchangeCodeForTokens(authorizationCode);
                actualRefreshToken = tokenData.refresh_token;
                console.log('Got refresh token from code exchange');
            } catch (error) {
                console.error('Failed to exchange code:', error.message);
            }
        }

        // Определяем токен для отзыва (приоритет: refresh_token > identity_token)
        const tokenToRevoke = actualRefreshToken || identityToken;
        const tokenType = actualRefreshToken ? 'refresh_token' : 'access_token';

        if (!tokenToRevoke) {
            return res.status(400).json({
                error: 'No valid token found for revocation'
            });
        }

        console.log(`Attempting to revoke ${tokenType}`);

        // Генерируем client_secret
        const clientSecret = generateAppleClientSecret();

        // Отзываем токен
        const revokeResponse = await fetch('https://appleid.apple.com/auth/revoke', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                client_id: 'com.astrDevProd.astrology.signin',
                client_secret: clientSecret,
                token: tokenToRevoke,
                token_type_hint: tokenType
            })
        });

        console.log('Apple revoke response status:', revokeResponse.status);

        // Получаем текст ответа для отладки
        const responseText = await revokeResponse.text();
        console.log('Apple revoke response body:', responseText);

        // Apple возвращает 200 для успешного отзыва
        if (revokeResponse.status === 200) {
            return res.status(200).json({
                success: true,
                message: 'Token revoked successfully',
                revokedTokenType: tokenType
            });
        } else {
            return res.status(400).json({
                success: false,
                error: 'Failed to revoke token',
                appleStatus: revokeResponse.status,
                appleResponse: responseText
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
        throw new Error(`Token exchange failed: ${response.status}`);
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
        sub: 'com.astrDevProd.astrology.signin',
    };

    return jwt.sign(payload, APPLE_PRIVATE_KEY, {
        algorithm: 'ES256',
        header: {
            kid: APPLE_KEY_ID,
            alg: 'ES256'
        }
    });
}