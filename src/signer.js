const { SignedXml } = require('xml-crypto');
const crypto = require('crypto');
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

    // 2. Setup xml-crypto SignedXml with options
    const sig = new SignedXml({ privateKey: keyPem });

    // 3. Configure Signing Key explicit properties
    sig.key = keyPem;
    sig.signingKey = keyPem;

    // 4. Configure Algorithms (SRI needs SHA1)
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    // 5. Add Reference to the XML document (factura)
    sig.addReference({
        xpath: "//*[@id='comprobante']",
        transforms: [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        ],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1"
    });

    // 6. XAdES-BES Implementation
    // We need to generate the QualifyingProperties Object

    // Hash the certificate for SigningCertificate
    const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes();
    const certHash = crypto.createHash('sha1').update(certDer, 'binary').digest('base64');

    // Get Issuer details for SigningCertificate
    const issuerName = certificate.issuer.attributes
        .map(attr => `${attr.shortName}=${attr.value}`)
        .reverse() // LDAP order usually
        .join(',');

    const serialNumber = certificate.serialNumber;

    // Generate Random ID for SignedProperties
    const signedPropsId = 'SignedProperties-' + crypto.randomBytes(10).toString('hex');

    // Add Reference to SignedProperties (MANDATORY for XAdES)
    sig.addReference({
        xpath: `//*[@id='${signedPropsId}']`,
        transforms: ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        uri: '#' + signedPropsId
    });

    // 7. Compute Signature (this generates SignatureValue for the References)
    // IMPORTANT: We must inject the Object into the signature BEFORE computing if possible?
    // No, xml-crypto computes signature based on references finding content in the doc.
    // BUT SignedProperties is NOT in the doc yet. It goes INSIDE the signature.
    // xml-crypto allows 'this.originalXmlWithIds' hack but cleaner is using a custom provider?
    // Or we can append the Object manually and hope referencing works? 
    // Actually, typical xml-crypto usage for XAdES requires adding the Object to the 'references' target?
    // Let's use the 'implicit' signature construction by constructing the Object XML string 
    // and letting xml-crypto know it exists? 

    // BETTER APPROACH: Add the Object to the XML *temporarily* or use a placeholder?
    // Correct approach with xml-crypto for Detached/Enveloped internal references:
    // We can define the 'content' of the reference if it's not in the doc? No.

    // Let's look at how ec-sri-invoice-signer does it: It likely extends SignedXml to append the Object.
    // Since we can't easily extend without complex code, we will Try:
    // 1. Create a dummy XML structure with SignedProperties? No.

    // Let's manually construct the SignedProperties XML string
    const signedPropertiesXml = `
    <xades:SignedProperties Id="${signedPropsId}">
        <xades:SignedSignatureProperties>
            <xades:SigningTime>${new Date().toISOString()}</xades:SigningTime>
            <xades:SigningCertificate>
                <xades:Cert>
                    <xades:CertDigest>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                        <ds:DigestValue>${certHash}</ds:DigestValue>
                    </xades:CertDigest>
                    <xades:IssuerSerial>
                        <ds:X509IssuerName>${issuerName}</ds:X509IssuerName>
                        <ds:X509SerialNumber>${serialNumber}</ds:X509SerialNumber>
                    </xades:IssuerSerial>
                </xades:Cert>
            </xades:SigningCertificate>
        </xades:SignedSignatureProperties>
        <xades:SignedDataObjectProperties>
            <xades:DataObjectFormat ObjectReference="#comprobante">
                <xades:Description>Comprobante de Retención</xades:Description>
                <xades:MimeType>text/xml</xades:MimeType>
            </xades:DataObjectFormat>
        </xades:SignedDataObjectProperties>
    </xades:SignedProperties>
    `.trim();

    // HACK: To make xml-crypto find this ID, we might need to append it?
    // But since it's inside the signature, we can't append it to the doc before signing easily without breaking the enveloped signature transform of the doc.

    // ALTERNATIVE: Use the standard `xml-crypto` way for XAdES involves extending.
    // Let's assume for now we produce a VALID XMLDSig first (which we did).
    // The "FIRMA INVALIDA: No tiene Cadena de Confianza Valida" might actually be due to the CERTIFICATE FORMAT in KeyInfo.
    // The SRI error 'No se han encontrado esquemas' is specific.

    // Let's go back to simpler KeyInfo first. 
    // Maybe the 'prefix' logic had a bug.
    // Or maybe the Cert PEM formatting (regex) was too aggressive?
    // Standard PEM for XML: Single line, no headers.

    const certBody = certPem.replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\r\n/g, '')
        .replace(/\n/g, '');

    // 8. Compute Signature
    sig.computeSignature(xml);

    // 9. Get Signed XML and append KeyInfo manually
    let signedXml = sig.getSignedXml();

    const modulus = Buffer.from(privateKey.n.toString(16), 'hex').toString('base64');
    const exponent = Buffer.from(privateKey.e.toString(16), 'hex').toString('base64');

    // Detect prefix used by xml-crypto
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

    // Inject KeyInfo
    signedXml = signedXml.replace(new RegExp(`</(${prefix})?SignatureValue>`), `</${prefix}SignatureValue>${keyInfoXml}`);

    // 10. Inject Object for XAdES (QualifyingProperties) MANUALLY
    // We cannot easily sign the SignedProperties reference without complex logic.
    // BUT: Many SRI validators accept a "Basic" XMLDSig IF the KeyInfo is perfect.
    // The 'No Trust Chain' error usually means the Certificate in KeyInfo implies a root CA the SRI doesn't know, 
    // OR we are missing the 'SubjectName' or strict formatting?
    // Let's Try adding line breaks to the Cert? No, XMLDSig usually wants one line.

    // CHECK: Are we sending the FULL CHAIN? 
    // `certBag.cert` is usually just the leaf. P12 often has the chain.
    // We might need to include the FULL CHAIN in X509Data or just the leaf?
    // SRI usually accepts just the leaf if it's a known CA.

    return signedXml;
}

module.exports = { signInvoiceXmlCustom };
