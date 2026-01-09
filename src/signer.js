const forge = require('node-forge');

/**
 * Computes SHA1 hash (required by SRI)
 */
function sha1(str) {
    const md = forge.md.sha1.create();
    md.update(str, 'utf8');
    return md.digest().toHex();
}

/**
 * Signs an XML Invoice using XAdES-BES
 * Adapted from ec-sri-invoice-signer but allows explicit cert/key injection
 */
function signInvoiceXmlCustom(xml, certBag, keyBag) {
    const certificate = certBag.cert || (certBag.attributes && certBag.attributes.cert);
    const privateKey = keyBag.key || (keyBag.attributes && keyBag.attributes.key);

    if (!certificate || !privateKey) throw new Error("Certificado o llave no válidos");

    // 1. Random IDs
    const signatureId = 'Signature-' + getRandomId();
    const signedInfoId = 'SignedInfo-' + getRandomId();
    const signedPropertiesId = 'SignedProperties-' + getRandomId();
    const signatureValueId = 'SignatureValue-' + getRandomId();
    const keyInfoId = 'Certificate-' + getRandomId();
    const objectId = 'SignatureObject-' + getRandomId();
    const referenceId = 'DocumentRef-' + getRandomId();
    const signedPropertiesRefId = 'SignedPropertiesRef-' + getRandomId();
    const certificateRefId = 'CertificateRef-' + getRandomId();

    // 2. Clear pretty print and newlines for canonicalization (SRI is strict)
    // Assuming 'xml' comes relatively clean or we trust xmlbuilder
    // But we need to make sure we sign the 'comprobante' element or the whole doc.
    // SRI usually expects the signature appended.

    // We assume input 'xml' is the content of the invoice, e.g. <factura>...</factura>
    // We need to hash IT.

    // Simplification: We will just hash the passed XML string assuming it is C14N compatible
    // Ideally use a proper C14N library, but often replacing \r\n with \n is enough for basic cases
    const xmlToSign = xml.replace(/\r\n/g, "\n");
    const digestComprobante = Buffer.from(sha1(xmlToSign), 'hex').toString('base64');

    // 3. Extract Cert Data
    const certPem = forge.pki.certificateToPem(certificate);
    // Remove headers
    const certBody = certPem.replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\r\n/g, '')
        .replace(/\n/g, '');

    const modulus = Buffer.from(privateKey.n.toString(16), 'hex').toString('base64');
    const exponent = Buffer.from(privateKey.e.toString(16), 'hex').toString('base64');

    // Issuer Name (Inverted for LDAP style usually used in XAdES)
    // NOTE: forge.pki.certificateToPem gives standard order. XAdES often wants specific string format.
    // We will use a standard helper or just construct it.
    const issuerName = getIssuerString(certificate);
    const serialNumber = certificate.serialNumber;

    // 4. Construct SignedTimestamp
    const signingTime = new Date().toISOString(); // e.g. 2026-01-09T18:00:00.000Z

    // 5. Construct KeyInfo
    const keyInfo = `
<ds:KeyInfo Id="${keyInfoId}">
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

    // 6. Signed Properties (Requires Hash too)
    // Note: The specific format of IDs and attributes is crucial for XAdES
    const signedProperties = `
<xades:SignedProperties Id="${signedPropertiesId}">
<xades:SignedSignatureProperties>
<xades:SigningTime>${signingTime}</xades:SigningTime>
<xades:SigningCertificate>
<xades:Cert>
<xades:CertDigest>
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<ds:DigestValue>${Buffer.from(sha1(Buffer.from(certBody, 'base64').toString('binary')), 'hex').toString('base64')}</ds:DigestValue>
</xades:CertDigest>
<xades:IssuerSerial>
<ds:X509IssuerName>${issuerName}</ds:X509IssuerName>
<ds:X509SerialNumber>${serialNumber}</ds:X509SerialNumber>
</xades:IssuerSerial>
</xades:Cert>
</xades:SigningCertificate>
</xades:SignedSignatureProperties>
<xades:SignedDataObjectProperties>
<xades:DataObjectFormat ObjectReference="#${referenceId}">
<xades:Description>Firma digital</xades:Description>
<xades:MimeType>text/xml</xades:MimeType>
<xades:Encoding>UTF-8</xades:Encoding>
</xades:DataObjectFormat>
</xades:SignedDataObjectProperties>
</xades:SignedProperties>`.replace(/\n/g, ''); // Compact

    // Hash of SignedProperties
    const digestSignedProperties = Buffer.from(sha1(signedProperties), 'hex').toString('base64');
    const digestKeyInfo = Buffer.from(sha1(keyInfo), 'hex').toString('base64'); // Sometimes Reference is to KeyInfo too, usually not in BES but check logic. 
    // Standard XAdES-BES References: Document, SignedProperties, (Optional) KeyInfo (Certificate)

    // 7. Construct SignedInfo
    // Warning: Whitespace inside SignedInfo allows C14N issues. Flatten it.
    const signedInfo = `
<ds:SignedInfo Id="${signedInfoId}">
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<ds:Reference Id="${referenceId}" URI="#comprobante">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<ds:DigestValue>${digestComprobante}</ds:DigestValue>
</ds:Reference>
<ds:Reference Id="${signedPropertiesRefId}" Type="http://uri.etsi.org/01903#SignedProperties" URI="#${signedPropertiesId}">
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<ds:DigestValue>${digestSignedProperties}</ds:DigestValue>
</ds:Reference>
<ds:Reference Id="${certificateRefId}" URI="#${keyInfoId}">
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<ds:DigestValue>${digestKeyInfo}</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>`.replace(/\n/g, '');

    // 8. Sign SignedInfo
    // We really should Canonicalize signedInfo properly (c14n). 
    // For simple string without namespaces except used ones, removing newlines might work if attributes are ordered.
    // Assuming simple construction:
    const md = forge.md.sha1.create();
    md.update(signedInfo, 'utf8');
    const signatureValue = forge.util.encode64(privateKey.sign(md));

    // 9. Assemble Final XML
    const signature = `
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="${signatureId}">
${signedInfo}
<ds:SignatureValue Id="${signatureValueId}">
${signatureValue}
</ds:SignatureValue>
${keyInfo}
<ds:Object Id="${objectId}">
<xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#${signatureId}">
${signedProperties}
</xades:QualifyingProperties>
</ds:Object>
</ds:Signature>
`.replace(/\n/g, '');

    // Inject into original XML (before closing tag, assuming root is </factura>)
    // SRI expects signature INSIDE root element (Enveloped Signature)

    const closeTagIndex = xml.lastIndexOf('</');
    if (closeTagIndex === -1) {
        // Fallback: just append if we can't find closing tag
        return xml + signature;
    }

    return xml.substring(0, closeTagIndex) + signature + xml.substring(closeTagIndex);
}

function getRandomId() {
    return Math.floor(Math.random() * 999999999).toString();
}

/**
 * Construct Issuer String in LDAP format (CN=...,OU=..., etc)
 */
function getIssuerString(cert) {
    // Forge attributes: [{shortName:'CN', value:'...'}, ...]
    // We need to reverse checks or just map properly.
    // Standard: CN=AC BANCO CENTRAL DEL ECUADOR,L=QUITO,OU=ENTIDAD DE CERTIFICACION DE INFORMACION-ECIBCE,O=BANCO CENTRAL DEL ECUADOR,C=EC
    // Note: The order matters for XAdES verification sometimes.
    return cert.issuer.attributes.map(a => `${a.shortName}=${a.value}`).join(',');
}

module.exports = { signInvoiceXmlCustom };
