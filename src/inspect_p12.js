const forge = require('node-forge');
const fs = require('fs');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Configuración Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

async function inspectP12() {
    try {
        // Obtenemos el emisor (asumiendo que hay uno solo o cogemos el primero para probar)
        const { data: emisor } = await supabase.from('emisores').select('*').limit(1).single();
        if (!emisor) {
            console.error("No se encontró emisor en BD");
            return;
        }

        console.log("Leyendo P12 para RUC:", emisor.ruc);
        const p12Buffer = fs.readFileSync(path.join(__dirname, '../firmas/firma.p12'));
        const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'));
        const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, emisor.firma_password);

        console.log("P12 Abierto correctamente.");
        console.log("Tenéis " + p12.safeContent.length + " SafeContents.");

        let certCount = 0;

        p12.safeContent.forEach(safeContents => {
            safeContents.safeBags.forEach(safeBag => {
                if (safeBag.certId) {
                    certCount++;
                    const cert = safeBag.cert;
                    console.log(`\n--- Certificado #${certCount} ---`);
                    console.log("Subject:", cert.subject.attributes.map(a => `${a.shortName}=${a.value}`).join(', '));
                    console.log("Issuer:", cert.issuer.attributes.map(a => `${a.shortName}=${a.value}`).join(', '));

                    // Extensions
                    const keyUsage = cert.getExtension('keyUsage');
                    if (keyUsage) {
                        console.log("Key Usage:", keyUsage.digitalSignature ? "DigitalSignature" : "", keyUsage.keyEncipherment ? "KeyEncipherment" : "", keyUsage.keyCertSign ? "KeyCertSign" : "");
                    } else {
                        console.log("Key Usage: NO TIENE");
                    }

                    const now = new Date();
                    console.log("Valido desde:", cert.validity.notBefore);
                    console.log("Valido hasta:", cert.validity.notAfter);
                    console.log("Expirado:", now > cert.validity.notAfter);
                }
            });
        });

    } catch (err) {
        console.error("Error leyendo P12:", err);
    }
}

inspectP12();
