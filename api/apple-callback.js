export default function handler(req, res) {
    console.log('Apple callback received');
    console.log('Method:', req.method);
    console.log('Body:', req.body);

    const PACKAGE_NAME = 'com.astrDevProd.astrology';
    const params = req.method === 'POST' ? req.body : req.query;

    // Apple передает user как JSON строку, нужно её распарсить
    if (params.user) {
        try {
            const userInfo = JSON.parse(params.user);
            console.log('User info:', userInfo);
            // Добавляется userIdentifier из распарсенного объекта
            if (userInfo.sub) {
                params.userIdentifier = userInfo.sub;
            }
        } catch (e) {
            console.log('Failed to parse user:', e);
        }
    }

    const intentUrl = `intent://callback?${new URLSearchParams(params).toString()}#Intent;package=${PACKAGE_NAME};scheme=signinwithapple;end`;

    console.log('Redirecting to:', intentUrl);
    res.redirect(307, intentUrl);
}