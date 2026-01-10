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
    // Generate the QualifyingProperties Object

    // Hash the certificate for SigningCertificate
    const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes();
    const certHash = crypto.createHash('sha1').update(certDer, 'binary').digest('base64');

    // Get Issuer details for SigningCertificate
    const issuerName = certificate.issuer.attributes
        .map(attr => `${attr.shortName}=${attr.value}`)
        .reverse()
        .join(', '); // Comma space usually

    const serialNumber = certificate.serialNumber;

    // Generate Random ID for SignedProperties
    const signedPropsId = 'SignedProperties-' + crypto.randomBytes(10).toString('hex');

    // Add Reference to SignedProperties (MANDATORY for XAdES)
    // IMPORTANT: 'uri' must match the Id
    sig.addReference({
        xpath: `//*[@Id='${signedPropsId}']`, // search by Id is stronger
        transforms: ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        uri: '#' + signedPropsId
    });

    // Construct the SignedProperties XML (Standalone with Namespaces)
    // We add xmlns declarations here to ensure C14N is stable when moved.
    const signedPropertiesXml = `
<xades:SignedProperties Id="${signedPropsId}" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
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
</xades:SignedProperties>`.replace(/\n\s*/g, ''); // Minify execution to avoid C14N whitespace issues

    // STRATEGY: DUMMY ROOT
    // We wrap the invoice + properties in a dummy root.
    // This allows xml-crypto to sign 'comprobante' (which is inside) without modifying it (no envelop signatures adding weirdness to the digest).

    const rootXml = `<root>${xml}${signedPropertiesXml}</root>`;

    // 7. Compute Signature on the Dummy Root XML
    try {
        sig.computeSignature(rootXml);
    } catch (e) {
        console.error("Error computing signature:", e);
        throw e;
    }

    // 8. Get Signed XML (Wrapped)
    let signedRootXml = sig.getSignedXml();

    // 9. EXTRACTION & ASSEMBLY
    // We need to extract the <Signature> block from signedRootXml
    // And inject it into the ORIGINAL 'xml' (inside <factura>, before close).

    // Extract Signature (Regex to handle potential prefixes)
    const signatureRegex = /<(\w+:)?Signature[\s\S]*?<\/\1Signature>/;
    const matchSigBlock = signedRootXml.match(signatureRegex);

    if (!matchSigBlock) throw new Error("No se pudo generar el bloque de firma");

    let signatureBlock = matchSigBlock[0];

    // Now we need to inject KeyInfo and Object into this signatureBlock
    // KeyInfo first
    const certBody = certPem.replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\r\n/g, '')
        .replace(/\n/g, '');

    const modulus = Buffer.from(privateKey.n.toString(16), 'hex').toString('base64');
    const exponent = Buffer.from(privateKey.e.toString(16), 'hex').toString('base64');

    const matchSig = signatureBlock.match(/<(\w+:)?Signature /);
    const prefix = matchSig && matchSig[1] ? matchSig[1] : '';

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
    signatureBlock = signatureBlock.replace(new RegExp(`</(${prefix})?SignatureValue>`), `</${prefix}SignatureValue>${keyInfoXml}`);

    // Object Injection (QualifyingProperties)
    // We ensure Signature has Id="Signature"
    signatureBlock = signatureBlock.replace(/<(\w+:)?Signature /, `<$1Signature Id="Signature" `);

    const objectXml = `<${prefix}Object><xades:QualifyingProperties Target="#Signature" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">${signedPropertiesXml}</xades:QualifyingProperties></${prefix}Object>`;

    // Append Object
    signatureBlock = signatureBlock.replace(new RegExp(`</(${prefix})?Signature>`), `${objectXml}</${prefix}Signature>`);

    // 10. Final Assembly: Inject fully constructed Signature into ORIGINAL xml
    // Finding closing tag of 'factura' (or whatever root)
    // The 'xml' input is the invoice XML.
    const rootClosingTag = '</factura>'; // Simplify assumption based on context
    // Or regex for last closing tag?
    // xml.lastIndexOf('</') ...

    const finalXml = xml.replace(rootClosingTag, signatureBlock + rootClosingTag);

    // CHECK: Are we sending the FULL CHAIN? 
    // `certBag.cert` is usually just the leaf. P12 often has the chain.
    // We might need to include the FULL CHAIN in X509Data or just the leaf?
    // SRI usually accepts just the leaf if it's a known CA.

    return finalXml;
}

module.exports = { signInvoiceXmlCustom };
