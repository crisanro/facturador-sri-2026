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
    console.log("   [DEBUG SIGNER] xml-crypto version:", require('xml-crypto/package.json').version);
    // Try passing privateKey in options if supported, or just init
    const sig = new SignedXml({ privateKey: keyPem });

    // 3. Configure Signing Key
    // Set properties explicitly too
    sig.key = keyPem;
    sig.signingKey = keyPem;
    console.log("   [DEBUG SIGNER] sig.signingKey set (String). Length:", sig.signingKey.length);

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

    // 7. Compute Signature
    sig.computeSignature(xml);

    // 8. Get Signed XML and append KeyInfo manually
    let signedXml = sig.getSignedXml();

    const certBody = certPem.replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\r\n/g, '')
        .replace(/\n/g, '');

    const modulus = Buffer.from(privateKey.n.toString(16), 'hex').toString('base64');
    const exponent = Buffer.from(privateKey.e.toString(16), 'hex').toString('base64');

    // Detect prefix used by xml-crypto (usually none or 'ds')
    const match = signedXml.match(/<(\w+:)?Signature /);
    const prefix = match && match[1] ? match[1] : '';

    const keyInfoXml = `
<${prefix}KeyInfo>
<${prefix}X509Data>
<${prefix}X509Certificate>
${certBody}
</${prefix}X509Certificate>
</${prefix}X509Data>
<${prefix}KeyValue>
<${prefix}RSAKeyValue>
<${prefix}Modulus>
${modulus}
</${prefix}Modulus>
<${prefix}Exponent>
${exponent}
</${prefix}Exponent>
</${prefix}RSAKeyValue>
</${prefix}KeyValue>
</${prefix}KeyInfo>`.replace(/\n/g, '');

    // Inject KeyInfo: Replace closing SignatureValue tag with itself + KeyInfo
    // Regex handles potential namespace prefix in replacement
    signedXml = signedXml.replace(new RegExp(`</(${prefix})?SignatureValue>`), `</${prefix}SignatureValue>${keyInfoXml}`);

    return signedXml;
}

module.exports = { signInvoiceXmlCustom };
