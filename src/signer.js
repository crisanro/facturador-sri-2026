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
    const sig = new SignedXml();

    // 3. Configure Signing Key
    // Set BOTH legacy and new properties to be safe against version mismatch
    sig.key = keyPem;
    sig.signingKey = Buffer.from(keyPem);
    console.log("   [DEBUG SIGNER] sig.signingKey set (Buffer). Length:", sig.signingKey.length);

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

    // 8. Get Signed XML and append KeyInfo manually since we removed provider
    let signedXml = sig.getSignedXml();

    // Manual KeyInfo Construction (Standard XAdES-BES)
    // We append this into the ds:Signature object if possible found in signedXml
    // But getSignedXml() returns the whole document? No, it returns the Signed Signature usually? 
    // Wait, getSignedXml() returns the *original XML* with the signature injected.

    // We need to inject <ds:KeyInfo> inside <ds:Signature>
    // The signature block looks like <ds:Signature ...> <ds:SignedInfo>...</ds:SignedInfo> <ds:SignatureValue>...</ds:SignatureValue> </ds:Signature>
    // We want to insert KeyInfo after SignatureValue.

    const certBody = certPem.replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\r\n/g, '')
        .replace(/\n/g, '');

    const modulus = Buffer.from(privateKey.n.toString(16), 'hex').toString('base64');
    const exponent = Buffer.from(privateKey.e.toString(16), 'hex').toString('base64');

    const keyInfoXml = `
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate>
${certBody}
</ds:X509Certificate>
</ds:X509Data>
<ds:KeyValue>
<ds:RSAKeyValue>
<ds:Modulus>
${modulus}
</ds:Modulus>
<ds:Exponent>
${exponent}
</ds:Exponent>
</ds:RSAKeyValue>
</ds:KeyValue>
</ds:KeyInfo>`.replace(/\n/g, '');

    // Inject KeyInfo
    signedXml = signedXml.replace('</ds:SignatureValue>', '</ds:SignatureValue>' + keyInfoXml);

    return signedXml;
}

module.exports = { signInvoiceXmlCustom };
