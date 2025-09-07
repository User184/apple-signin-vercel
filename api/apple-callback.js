export default function handler(req, res) {
    console.log('Apple callback received');
    console.log('Method:', req.method);
    console.log('Body:', req.body);
    console.log('Query:', req.query);

    const PACKAGE_NAME = 'com.astrDevProd.astrology';

    // Параметры из POST body или GET query
    const params = req.method === 'POST' ? req.body : req.query;

    // Формируется Intent URL
    const intentUrl = `intent://callback?${new URLSearchParams(params).toString()}#Intent;package=${PACKAGE_NAME};scheme=signinwithapple;end`;

    console.log('Redirecting to:', intentUrl);

    // HTTP 307 redirect
    res.redirect(307, intentUrl);
}