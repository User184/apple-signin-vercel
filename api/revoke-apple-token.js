import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { refreshToken, accessToken } = req.body;

        if (!refreshToken && !accessToken) {
            return res.status(400).json({ error: 'Token required' });
        }

        console.log('Attempting to revoke Apple token');

        // Генерация client_secret для Apple API
        const clientSecret = generateAppleClientSecret();

        // Отзывrefresh token (приоритетный)
        const tokenToRevoke = refreshToken || accessToken;
        const tokenType = refreshToken ? 'refresh_token' : 'access_token';

        const response = await fetch('https://appleid.apple.com/auth/revoke', {
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

        console.log('Apple revoke response status:', response.status);

        if (response.ok || response.status === 200) {
            console.log('Apple token successfully revoked');
            return res.status(200).json({
                success: true,
                message: 'Token revoked successfully'
            });
        } else {
            const errorText = await response.text();
            console.error('Apple revoke error:', response.status, errorText);
            return res.status(400).json({
                success: false,
                error: 'Failed to revoke token',
                details: errorText
            });
        }

    } catch (error) {
        console.error('Error revoking Apple token:', error);
        return res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
}

function generateAppleClientSecret() {
    // Apple credentials
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
        exp: now + 3600, // 1 час
        aud: 'https://appleid.apple.com',
        sub: 'com.astrDevProd.astrology.signin',
    };

    // Подписываем JWT с Apple private key
    return jwt.sign(payload, APPLE_PRIVATE_KEY, {
        algorithm: 'ES256',
        header: {
            kid: APPLE_KEY_ID,
            alg: 'ES256'
        }
    });
}