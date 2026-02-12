const { KYC_BASE_URL } = require('./config')

async function startSession(KYC_ACCESS_TOKEN) {

    const res = await fetch(`${KYC_BASE_URL}/e-kyc/verification/session`, {
        method: 'POST',
        headers: { 'x-kyc-access-token': KYC_ACCESS_TOKEN }
    });
    const result = await res.json();
    return result.data.sessionId;

}
module.exports = {
    startSession,
}