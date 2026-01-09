const { SignedXml } = require('xml-crypto');
const { DOMParser } = require('@xmldom/xmldom');
const forge = require('node-forge');

/**
 * Signs an XML Invoice using XAdES-BES
 * Adapted from ec-sri-invoice-signer but allows explicit cert/key injection
 */
function signInvoiceXmlCustom(xml, certBag, keyBag) {
    const certificate = certBag.cert || (certBag.attributes && certBag.attributes.cert);
    const privateKey = keyBag.key || (keyBag.attributes && keyBag.attributes.key);

    if (!certificate || !privateKey) throw new Error("Certificado o llave no válidos");

    // 1. Convert Forge Keys/Certs to PEM strings for xml-crypto
    const certPem = forge.pki.certificateToPem(certificate);
    // Private Key strictly in PKCS8 PEM format often works best, or standard PEM
    const keyPem = forge.pki.privateKeyToPem(privateKey);

    console.log("   [DEBUG SIGNER] Cert PEM length:", certPem.length);
    console.log("   [DEBUG SIGNER] Key PEM length:", keyPem ? keyPem.length : "NULL");
    if (keyPem) console.log("   [DEBUG SIGNER] Key PEM Header:", keyPem.substring(0, 40));

    // 2. Setup xml-crypto SignedXml
    const sig = new SignedXml();

    // 3. Configure Signing Key
    sig.signingKey = keyPem;
    console.log("   [DEBUG SIGNER] sig.signingKey set. Length:", sig.signingKey ? sig.signingKey.length : "NULL");

    // 4. Configure Algorithms (SRI needs SHA1)
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    // 5. Add Reference
    sig.addReference({
        xpath: "//*[@id='comprobante']",
        transforms: [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        ],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1"
    });

    // 6. Add KeyInfo (X509Certificate)
    // xml-crypto usually adds KeyInfo automatically if provided? No, usually manual or via getKeyInfoContent

    // Custom KeyInfo Provider
    sig.keyInfoProvider = {
        getKeyInfo: function (key, prefix) {
            const certBody = certPem.replace(/-----BEGIN CERTIFICATE-----/g, '')
                .replace(/-----END CERTIFICATE-----/g, '')
                .replace(/\r\n/g, '')
                .replace(/\n/g, '');
            prefix = prefix ? prefix + ':' : '';
            return `<${prefix}X509Data><${prefix}X509Certificate>${certBody}</${prefix}X509Certificate></${prefix}X509Data>`;
        },
        getKey: function (keyInfo) {
            return keyPem;
        }
    };

    // 7. Compute Signature
    sig.computeSignature(xml);

    // 8. Get Signed XML
    return sig.getSignedXml();
}

module.exports = { signInvoiceXmlCustom };
