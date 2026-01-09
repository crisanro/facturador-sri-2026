const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

// Uso: node src/inspect_p12_manual.js <RUTA_P12> <PASSWORD>
const p12Path = process.argv[2];
const p12Password = process.argv[3];

if (!p12Path || !p12Password) {
    console.log("❌ Error: Faltan argumentos.");
    console.log("Uso correcto: node src/inspect_p12_manual.js <RUTA_DEL_ARCHIVO_P12> <CONTRASEÑA>");
    process.exit(1);
}

try {
    const absolutePath = path.isAbsolute(p12Path) ? p12Path : path.join(process.cwd(), p12Path);
    console.log(`\n📂 ANALISÍS DE ARCHIVO P12: ${path.basename(absolutePath)}`);

    if (!fs.existsSync(absolutePath)) {
        console.error("❌ El archivo no existe.");
        process.exit(1);
    }

    const p12Buffer = fs.readFileSync(absolutePath);
    const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'));
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, p12Password);

    console.log("✅ Contraseña correcta. Descifrado exitoso.");

    const safes = p12.safeContent || p12.safeContents;
    console.log(`📦 Estructura P12: ${safes.length} contenedores seguros (SafeContents).`);

    let signingCertsFound = 0;
    let totalCerts = 0;

    safes.forEach((sc, i) => {
        sc.safeBags.forEach((sb, j) => {
            let cert = sb.cert;
            if (!cert && sb.type === forge.pki.oids.certBag) {
                cert = sb.cert || (sb.attributes && sb.attributes.cert);
            }

            if (cert) {
                totalCerts++;
                const subject = cert.subject.getField('CN') ? cert.subject.getField('CN').value : 'Sin CN';
                const issuer = cert.issuer.getField('CN') ? cert.issuer.getField('CN').value : 'Sin CN';
                const validTo = cert.validity.notAfter;
                const ku = cert.getExtension('keyUsage');

                const canSign = ku && ku.digitalSignature;
                const isExpired = new Date() > validTo;

                console.log(`\n--- � CERTIFICADO #${totalCerts} ---`);
                console.log(`   🏷️  Nombre (Subject): ${subject}`);
                console.log(`   🏢 Emisor (Issuer):  ${issuer}`);
                console.log(`   📅 Vence:            ${validTo.toISOString().split('T')[0]}`);

                if (ku) {
                    console.log(`   🔐 Permisos:         [${ku.digitalSignature ? 'FIRMA DIGITAL' : ''} ${ku.keyEncipherment ? 'CIFRADO' : ''} ${ku.nonRepudiation ? 'NO REPUDIO' : ''}]`);
                } else {
                    console.log(`   🔐 Permisos:         NO DEFINIDOS (Probable CA Root)`);
                }

                if (canSign) {
                    console.log("   ✅ ESTE ES UN CERTIFICADO DE FIRMA VÁLIDO (Candidato para SRI)");
                    signingCertsFound++;
                } else {
                    console.log("   ⚠️  ESTE CERTIFICADO NO SIRVE PARA FIRMAR FACTURAS (Es Root o Cifrado)");
                }
            }
        });
    });

    console.log("\n---------------------------------------------------");
    console.log(`RESULTADO: Encontrados ${totalCerts} certificados.`);
    if (signingCertsFound > 0) {
        console.log(`✅ SE ENCONTRÓ ${signingCertsFound} CERTIFICADO(S) VÁLIDO(S) PARA FIRMAR.`);
        console.log("El sistema debería seleccionar automáticamente uno de estos.");
    } else {
        console.log("❌ ERROR GRAVE: NO SE ENCONTRÓ NINGÚN CERTIFICADO CON PERMISO 'DIGITAL SIGNATURE'.");
        console.log("Tu archivo P12 podría estar corrupto, ser solo de cifrado, o contener solo la cadena de confianza (Root CA) sin tu llave privada.");
    }

} catch (err) {
    console.error("\n❌ Error al leer P12:", err.message);
}
