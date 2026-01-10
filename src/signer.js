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

    // STRATEGY: Append SignedProperties to the XML *temporarily* so xml-crypto can find and hash it.
    // We append it inside the root element so strict parsers don't complain about multiple roots.
    // NOTE: This modifies 'xml' to 'xmlWithProps'
    // We must ensure this temporary insertion matches what the 'xpath' expects.
    // XPath `//*[@Id='...']` should find it anywhere.

    // Inject at the end of content, before closing root.
    // Find closing tag of root (factura)
    const rootClosingTag = '</factura>';
    const xmlWithProps = xml.replace(rootClosingTag, signedPropertiesXml + rootClosingTag);

    // 7. Compute Signature on the Modified XML
    try {
        sig.computeSignature(xmlWithProps);
    } catch (e) {
        console.error("Error computing signature:", e);
        throw e;
    }

    // 8. Get Signed XML which now has Signature + SignedProperties (in body)
    let signedXml = sig.getSignedXml();

    // 9. CLEANUP: Move SignedProperties into the Signature Object

    // a. Remove the SignedProperties we injected in the body
    // Using simple replacement since we know the exact string (if minified) or regex
    // BE CAREFUL: sig.getSignedXml() returns the *original xml* (modified) PLUS the signature?
    // xml-crypto usually inserts signature before root close.
    // So signedXml likely looks like: <factura> ... <SignedProperties>...</SignedProperties> <Signature>...</Signature> </factura>
    // OR <factura> ... <SignedProperties>...</SignedProperties> ... <Signature>... </factura>

    // We need to cut out the <xades:SignedProperties... </xades:SignedProperties> block
    // And paste it inside <ds:Object><xades:QualifyingProperties ...>...

    // Regex to extract the Full Node
    const propsRegex = /<xades:SignedProperties[\s\S]*?<\/xades:SignedProperties>/;
    const matchProps = signedXml.match(propsRegex);

    if (!matchProps) {
        console.error("Could not find SignedProperties in signed XML to move it.");
        // Fallback?
    } else {
        const extractedProps = matchProps[0];

        // Remove from body
        signedXml = signedXml.replace(extractedProps, '');

        // Prepare Object Wrapper
        // Structure: <ds:Object><xades:QualifyingProperties Target="#SignatureId"><SignedProperties...
        // We need the Signature ID? SRI signatures might not require Signature ID if Target is implied? 
        // Standard XAdES: QualifyingProperties Target="#SignatureId" is common. 
        // xml-crypto auto-generates Signature Id? usually simply 'Signature' or none.
        // Let's check signedXml for Signature ID.

        // Let's wrap SignedProperties in QualifyingProperties
        const objectXml = `<ds:Object><xades:QualifyingProperties Target="#Signature" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">${extractedProps}</xades:QualifyingProperties></ds:Object>`;

        // Detect prefix again to inject correctly (KeyInfo was step 9 before, now we do this too)
        const matchSig = signedXml.match(/<(\w+:)?Signature /);
        const prefix = matchSig && matchSig[1] ? matchSig[1] : '';

        // We also need to ensure Signature has Id="Signature" so the Target matches
        // Regex replace Signature tag
        signedXml = signedXml.replace(/<(\w+:)?Signature /, `<$1Signature Id="Signature" `);

        // Append Object to Signature (before closing </ds:Signature>)
        signedXml = signedXml.replace(new RegExp(`</(${prefix})?Signature>`), `${objectXml}</${prefix}Signature>`);
    }

    // 10. Manual KeyInfo Injection (From previous step, keeping it for robustness)
    const certBody = certPem.replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\r\n/g, '')
        .replace(/\n/g, '');

    const modulus = Buffer.from(privateKey.n.toString(16), 'hex').toString('base64');
    const exponent = Buffer.from(privateKey.e.toString(16), 'hex').toString('base64');

    const matchSig = signedXml.match(/<(\w+:)?Signature /);
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

    // Inject KeyInfo: Replace closing SignatureValue with itself + KeyInfo
    // Be careful not to replace twice if we ran before? 
    // Just replace once.
    signedXml = signedXml.replace(new RegExp(`</(${prefix})?SignatureValue>`), `</${prefix}SignatureValue>${keyInfoXml}`);

    // CHECK: Are we sending the FULL CHAIN? 
    // `certBag.cert` is usually just the leaf. P12 often has the chain.
    // We might need to include the FULL CHAIN in X509Data or just the leaf?
    // SRI usually accepts just the leaf if it's a known CA.

    return signedXml;
}

module.exports = { signInvoiceXmlCustom };
