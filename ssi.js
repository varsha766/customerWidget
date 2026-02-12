const { KYC_API_SECRET, SSI_API_SECRET, X_ISSUER_VERMETHOD_ID, X_ISSUER_DID, DEVELOPER_DASHBOARD_SERVICE_BASE_URL, DOMAIN, SSI_BASE_URL, KYC_BASE_URL } = require('./config')

async function createDID(namespace = "", SSI_ACCESS_TOKEN) {
    const url = `${SSI_BASE_URL}/did/create`;
    const requestBody = {
        namespace: namespace
    };

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + SSI_ACCESS_TOKEN
            },
            body: JSON.stringify(requestBody)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`Error ${response.status}: ${JSON.stringify(errorData)}`);
        }
        const resp = await response.json();
        // type == Ed25519VerificationKey2020
        return {
            did: resp.did,
            verficationMethodId: resp.metaData.didDocument.verificationMethod.find(x => x.type == 'Ed25519VerificationKey2020').id
        };
    } catch (error) {
        console.error("Failed to create DID:", error);
        throw error;
    }
}



module.exports = { createDID }