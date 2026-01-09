const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

// Uso: node src/inspect_p12_manual.js <RUTA_P12> <PASSWORD>
const p12Path = process.argv[2];
const p12Password = process.argv[3];

if (!p12Path || !p12Password) {
    console.log("❌ Error: Faltan argumentos.");
    console.log("Uso correcto: node src/inspect_p12_manual.js <RUTA_DEL_ARCHIVO_P12> <CONTRASEÑA>");
    console.log("Ejemplo: node src/inspect_p12_manual.js ./firmas/firma.p12 MiContraseña123");
    process.exit(1);
}

try {
    const absolutePath = path.isAbsolute(p12Path) ? p12Path : path.join(process.cwd(), p12Path);
    console.log(`\n📂 Leyendo archivo: ${absolutePath}`);

    if (!fs.existsSync(absolutePath)) {
        console.error("❌ El archivo no existe en la ruta especificada.");
        process.exit(1);
    }

    const p12Buffer = fs.readFileSync(absolutePath);
    const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'));

    console.log("🔑 Intentando descifrar con la contraseña proporcionada...");
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, p12Password);

    console.log("✅ P12 Descifrado correctamente.");

    const safes = p12.safeContent || p12.safeContents;
    console.log(`📦 Contenido Seguro (SafeContents): ${safes.length} bloques.`);

    let certCount = 0;
    safes.forEach((sc, i) => {
        console.log(`\n--- Bloque #${i + 1} (${sc.safeBags.length} elementos) ---`);
        sc.safeBags.forEach((sb, j) => {
            let cert = sb.cert;
            // Intentar encontrar el certificado si no está directo en sb.cert
            if (!cert && sb.type === forge.pki.oids.certBag) {
                cert = sb.cert || (sb.attributes && sb.attributes.cert);
            }

            if (cert) {
                certCount++;
                console.log(`   📜 Certificado #${certCount} encontrado`);

                try {
                    const subject = cert.subject.attributes.map(a => `${a.shortName}=${a.value}`).join(', ');
                    const issuer = cert.issuer.attributes.map(a => `${a.shortName}=${a.value}`).join(', ');
                    console.log(`      👤 Sujeto (Dueño): ${subject}`);
                    console.log(`      🏢 Emisor (Entidad): ${issuer}`);

                    const validFrom = cert.validity.notBefore;
                    const validTo = cert.validity.notAfter;
                    console.log(`      📅 Validez: ${validFrom} a ${validTo}`);

                    const ku = cert.getExtension('keyUsage');
                    if (ku) {
                        console.log(`      🔐 Key Usage (Usos de Llave):`);
                        console.log(`         - Digital Signature: ${ku.digitalSignature}`);
                        console.log(`         - Non Repudiation: ${ku.nonRepudiation}`);
                        console.log(`         - Key Encipherment: ${ku.keyEncipherment}`);

                        if (!ku.digitalSignature) {
                            console.log("         ⚠️ ALERTA: Este certificado NO tiene permiso de Firma Digital.");
                        }
                    } else {
                        console.log("      ⚠️ Key Usage: NO DEFINIDO (Puede ser causa de error)");
                    }

                } catch (err) {
                    console.log("      ❌ Error leyendo detalles del certificado:", err.message);
                }
            } else if (sb.key) {
                console.log(`   🔑 Llave Privada encontrada (Bag Type: ${sb.type})`);
            } else {
                console.log(`   ❓ Otro elemento (Bag Type: ${sb.type})`);
            }
        });
    });

    if (certCount === 0) {
        console.log("\n⚠️ No se encontraron certificados X.509 en este archivo P12.");
    }

} catch (err) {
    console.error("\n❌ Error Crítico:");
    console.error(err.message);
    if (err.message.includes("Invalid password") || err.message.includes("mac invalid")) {
        console.error("💡 Pista: La contraseña parece ser incorrecta.");
    }
}
