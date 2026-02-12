const { KYC_API_SECRET, SSI_API_SECRET, X_ISSUER_VERMETHOD_ID, X_ISSUER_DID, DEVELOPER_DASHBOARD_SERVICE_BASE_URL, DOMAIN, SSI_BASE_URL, KYC_BASE_URL } = require('./config')
const fs = require('fs').promises;
const path = require('path');
const TOKEN_FILE = path.join(__dirname, 'tokens.json');

async function generateAccessTokensForKYCandSSI(api_secret, type) {
    const path = "/api/v1/app/oauth"

    try {
        const res = await fetch(`${DEVELOPER_DASHBOARD_SERVICE_BASE_URL}${path}?grant_type=${type}`, {
            method: 'POST',
            headers: { 'X-Api-Secret-Key': api_secret }
        });
        const result = await res.json();
        return result.access_token

    } catch (e) {
        console.error(e.message)
    }
}

// Helper function to decode JWT payload without external libraries
function getJwtExpiry(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = Buffer.from(base64, 'base64').toString();
        const payload = JSON.parse(jsonPayload);

        // 'exp' is usually in seconds
        return payload.exp ? payload.exp * 1000 : 0;
    } catch (e) {
        return 0; // If decoding fails, treat as expired
    }
}

async function prepareAccessTokens() {
    try {
        let cachedTokens = null;

        // 1. Load from file
        try {
            const data = await fs.readFile(TOKEN_FILE, 'utf8');
            cachedTokens = JSON.parse(data);
        } catch (err) {
            console.log('No token file found.');
        }

        const now = Date.now();

        // 2. Validate existence and expiration for BOTH tokens
        const isMissing = !cachedTokens || !cachedTokens.KYC_ACCESS_TOKEN || !cachedTokens.SSI_ACCESS_TOKEN;

        // Check expiry if tokens exist (adding a 60-second buffer for safety)
        const isExpired = !isMissing && (
            getJwtExpiry(cachedTokens.KYC_ACCESS_TOKEN) <= (now + 60000) ||
            getJwtExpiry(cachedTokens.SSI_ACCESS_TOKEN) <= (now + 60000)
        );

        if (isMissing || isExpired) {
            console.log(isExpired ? 'Tokens are expired/expiring soon.' : 'Tokens missing.');

            const KYC_ACCESS_TOKEN = await generateAccessTokensForKYCandSSI(KYC_API_SECRET, 'access_service_kyc');
            const SSI_ACCESS_TOKEN = await generateAccessTokensForKYCandSSI(SSI_API_SECRET, 'access_service_ssi');

            const tokensToSave = { KYC_ACCESS_TOKEN, SSI_ACCESS_TOKEN };

            await fs.writeFile(TOKEN_FILE, JSON.stringify(tokensToSave, null, 2));
            return tokensToSave;
        }

        console.log('Tokens are still valid. Reusing from cache.');
        return cachedTokens;

    } catch (e) {
        console.error('Error:', e.message);
    }
}


// This API call can be skipp if did-jwt is used
async function authenticateAndIssueKycUserAccessToken(claims, KYC_ACCESS_TOKEN, SSI_ACCESS_TOKEN, sessionId) {
    const data = await fetch(`${SSI_BASE_URL}/did/auth/issue-jwt`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${SSI_ACCESS_TOKEN}`,
        },
        body: JSON.stringify({
            "issuer": {
                "verificationmethodId": X_ISSUER_VERMETHOD_ID,
                "did": X_ISSUER_DID
            },
            "audience": DOMAIN,
            "claims": claims,
            "ttlSeconds": 3600

        })

    })
    if (!data.ok) {
        const err = await data.text();
        throw new Error(`Token API failed: ${err}`);
    }
    const json = await data.json();
    const token = await getBearerToken(json.accessToken, KYC_ACCESS_TOKEN, SSI_ACCESS_TOKEN, sessionId)
    return token
}

// 
async function getBearerToken(didJwtToken, KYC_ACCESS_TOKEN, SSI_ACCESS_TOKEN, sessionId) {
    const data = await fetch(`${KYC_BASE_URL}/e-kyc/verification/auth`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "x-ssi-access-token": SSI_ACCESS_TOKEN,
            "x-kyc-access-token": KYC_ACCESS_TOKEN,
            "Authorization": `Bearer ${didJwtToken}`,
        },
        body: JSON.stringify({
            provider: "third-party-auth",
            sessionId
        })
    })
    if (!data.ok) {
        const err = await data.text();
        throw new Error(`Token API failed to generate kycUserAccessToken: ${err}`);
    }
    const json = await data.json();
    return json.data.kycServiceUserAccessToken
}

module.exports = {
    prepareAccessTokens,
    authenticateAndIssueKycUserAccessToken,
}