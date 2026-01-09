const { createClient } = require('@supabase/supabase-js');
const forge = require('node-forge');
const { create } = require('xmlbuilder2');
const { signInvoiceXml } = require('ec-sri-invoice-signer');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { XMLParser } = require('fast-xml-parser');
const { generarClaveAcceso } = require('./utils');
const { calcularTotalesEImpuestos } = require('./calculadoraSri');

// Iniciar Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const parser = new XMLParser({ ignoreAttributes: false });

const URLS_SRI = {
    pruebas: {
        recepcion: 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl',
        autorizacion: 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl'
    },
    produccion: {
        recepcion: 'https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl',
        autorizacion: 'https://cel.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl'
    }
};

async function procesarFacturaCompleta(inputCliente) {
    console.log("1. Iniciando proceso para:", inputCliente.rucEmisor);
    console.log("   Datos recibidos:", JSON.stringify(inputCliente).substring(0, 100)); // Log breve

    // --- A. BUSCAR EMISOR EN BD ---
    const { data: emisor, error } = await supabase
        .from('emisores')
        .select('*')
        .eq('ruc', inputCliente.rucEmisor)
        .single();

    if (error || !emisor) throw new Error("Emisor no encontrado en Supabase. ¿Ya lo registraste?");

    // --- B. SECUENCIAL ---
    const nuevoSecuencial = emisor.secuencial_actual + 1;
    const secuencialStr = nuevoSecuencial.toString().padStart(9, '0');
    await supabase.from('emisores').update({ secuencial_actual: nuevoSecuencial }).eq('id', emisor.id);

    // --- C. CALCULOS MATEMÁTICOS ---
    const calculos = calcularTotalesEImpuestos(inputCliente.items);

    // --- D. GENERAR XML ---
    const hoy = new Date().toISOString().split('T')[0];
    // Nota: El ambiente viene de la BD del emisor (1 o 2)
    const claveAcceso = generarClaveAcceso(hoy, '01', emisor.ruc, emisor.ambiente.toString(), '001001', secuencialStr);

    const doc = create({ version: '1.0', encoding: 'UTF-8' }).ele('factura', { id: 'comprobante', version: '1.1.0' });

    // Info Tributaria
    const infoTrib = doc.ele('infoTributaria');
    infoTrib.ele('ambiente').txt(emisor.ambiente);
    infoTrib.ele('tipoEmision').txt('1');
    infoTrib.ele('razonSocial').txt(emisor.razon_social);
    infoTrib.ele('ruc').txt(emisor.ruc);
    infoTrib.ele('claveAcceso').txt(claveAcceso);
    infoTrib.ele('codDoc').txt('01');
    infoTrib.ele('estab').txt('001'); // Podrías parametrizar esto en la BD también
    infoTrib.ele('ptoEmi').txt('001');
    infoTrib.ele('secuencial').txt(secuencialStr);
    infoTrib.ele('dirMatriz').txt(emisor.direccion_matriz);

    // --- NUEVO: RIMPE y Agente de Retención ---
    if (emisor.contribuyente_rimpe) {
        infoTrib.ele('contribuyenteRimpe').txt(emisor.contribuyente_rimpe);
    }
    if (emisor.agente_retencion) {
        infoTrib.ele('agenteRetencion').txt(emisor.agente_retencion);
    }

    // Info Factura
    const infoFac = doc.ele('infoFactura');
    infoFac.ele('fechaEmision').txt(hoy.split('-').reverse().join('/'));
    infoFac.ele('dirEstablecimiento').txt(emisor.direccion_matriz);
    infoFac.ele('obligadoContabilidad').txt('NO');
    infoFac.ele('tipoIdentificacionComprador').txt(inputCliente.cliente.tipoId);
    infoFac.ele('razonSocialComprador').txt(inputCliente.cliente.razonSocial);
    infoFac.ele('identificacionComprador').txt(inputCliente.cliente.identificacion);
    infoFac.ele('totalSinImpuestos').txt(calculos.totales.totalSinImpuestos);
    infoFac.ele('totalDescuento').txt(calculos.totales.totalDescuento);

    const totalConImpuestosXml = infoFac.ele('totalConImpuestos');
    calculos.totalConImpuestosXml.forEach(imp => {
        const i = totalConImpuestosXml.ele('totalImpuesto');
        i.ele('codigo').txt(imp.codigo);
        i.ele('codigoPorcentaje').txt(imp.codigoPorcentaje);
        i.ele('baseImponible').txt(imp.baseImponible);
        i.ele('valor').txt(imp.valor);
    });

    infoFac.ele('propina').txt('0.00');
    infoFac.ele('importeTotal').txt(calculos.totales.importeTotal);
    infoFac.ele('moneda').txt('DOLAR');

    const pagos = infoFac.ele('pagos');

    // --- NUEVO: Formas de Pago Dinámicas ---
    if (inputCliente.pagos && Array.isArray(inputCliente.pagos) && inputCliente.pagos.length > 0) {
        inputCliente.pagos.forEach(pagoItem => {
            const p = pagos.ele('pago');
            p.ele('formaPago').txt(pagoItem.formaPago);
            p.ele('total').txt(pagoItem.total.toFixed(2));
            if (pagoItem.plazo) p.ele('plazo').txt(pagoItem.plazo);
            if (pagoItem.unidadTiempo) p.ele('unidadTiempo').txt(pagoItem.unidadTiempo);
        });
    } else {
        // Fallback por defecto: Código 20 (Otros con utilización del sistema financiero)
        pagos.ele('pago').ele('formaPago').txt('20').up().ele('total').txt(calculos.totales.importeTotal);
    }

    // Detalles
    const detalles = doc.ele('detalles');
    calculos.detallesXml.forEach(item => {
        const det = detalles.ele('detalle');
        det.ele('codigoPrincipal').txt(item.codigoPrincipal);
        det.ele('descripcion').txt(item.descripcion);
        det.ele('cantidad').txt(item.cantidad);
        det.ele('precioUnitario').txt(item.precioUnitario);
        det.ele('descuento').txt(item.descuento);
        det.ele('precioTotalSinImpuesto').txt(item.precioTotalSinImpuesto);
        const imps = det.ele('impuestos');
        item.impuestos.forEach(impItem => {
            const imp = imps.ele('impuesto');
            imp.ele('codigo').txt(impItem.codigo);
            imp.ele('codigoPorcentaje').txt(impItem.codigoPorcentaje);
            imp.ele('tarifa').txt(impItem.tarifa);
            imp.ele('baseImponible').txt(impItem.baseImponible);
            imp.ele('valor').txt(impItem.valor);
        });
    });

    const xmlString = doc.end({ prettyPrint: false });

    // --- E. FIRMAR XML ---
    // NOTA: Para producción, el P12 no debería estar en archivo local sino en storage seguro o base64 en BD.
    // Por ahora leemos del archivo local que subirás.
    // --- FILTER P12 (FIX FIRMA INVALIDA) ---
    // Extract ONLY the certificate with 'Digital Signature' capability
    const p12BufferOriginal = fs.readFileSync(path.join(__dirname, '../firmas/firma.p12'));
    let p12BufferToUse = p12BufferOriginal;
    const password = emisor.firma_password;

    let targetCertBag = null;
    let targetKeyBag = null;

    try {
        const p12Asn1 = forge.asn1.fromDer(p12BufferOriginal.toString('binary'));
        const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);
        const safes = p12.safeContent || p12.safeContents;

        console.log("   [FIX] Buscando certificado y llave manual...");

        safes.forEach(sc => {
            sc.safeBags.forEach(sb => {
                // 1. Is Certificate?
                if (sb.type === forge.pki.oids.certBag) {
                    const cert = sb.cert || (sb.attributes && sb.attributes.cert);
                    if (cert) {
                        const ku = cert.getExtension('keyUsage');
                        if (ku && ku.digitalSignature) {
                            console.log("   [FIX] Certificado de firma encontrado:", cert.subject.getField('CN').value);
                            targetCertBag = sb;
                        }
                    }
                }
                // 2. Is Private Key?
                else if (sb.type === forge.pki.oids.pkcs8ShroudedKeyBag || sb.type === forge.pki.oids.keyBag) {
                    targetKeyBag = sb;
                }
            });
        });

    } catch (e) {
        console.error("   [FIX ERROR] Error al parsear P12 para extracción de certificado:", e.message);
    }

    let xmlFirmado = '';
    if (targetCertBag && targetKeyBag) {
        console.log("   [FIX] Usando Custom Signer con certificado verificado...");
        try {
            // Usamos nuestro firmador manual pasando los objetos Forge directos
            xmlFirmado = signInvoiceXmlCustom(xmlString, targetCertBag, targetKeyBag);
            console.log("   [FIX] FIRMA CUSTOM GENERADA EXITOSAMENTE!");
        } catch (errSign) {
            console.error("   [FIX ERROR] Falló firma custom:", errSign);
            throw errSign;
        }
    } else {
        console.log("   [FIX WARNING] No se encontró certificado válido. Usando método legacy...");
        xmlFirmado = signInvoiceXml(xmlString, p12BufferOriginal, { pkcs12Password: password });
    }

    // --- F. GUARDAR EN BD (ESTADO: FIRMADO) ---
    const { data: facturaDB } = await supabase.from('facturas').insert({
        emisor_id: emisor.id,
        clave_acceso: claveAcceso,
        secuencial: secuencialStr,
        total_sin_impuestos: calculos.totales.totalSinImpuestos,
        total_iva: calculos.totales.totalIva,
        importe_total: calculos.totales.importeTotal,
        xml_generado: xmlFirmado,
        estado_sri: 'FIRMADO'
    }).select().single();

    // --- G. ENVIAR AL SRI ---
    const urls = emisor.ambiente === 2 ? URLS_SRI.produccion : URLS_SRI.pruebas;
    const xmlBase64 = Buffer.from(xmlFirmado).toString('base64');

    const soapRecepcion = `
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ec="http://ec.gob.sri.ws.recepcion">
       <soapenv:Header/>
       <soapenv:Body>
          <ec:validarComprobante><xml>${xmlBase64}</xml></ec:validarComprobante>
       </soapenv:Body>
    </soapenv:Envelope>`;

    try {
        console.log("Enviando a SRI Recepción...");
        const { data: dataRecepcion } = await axios.post(urls.recepcion, soapRecepcion, {
            headers: { 'Content-Type': 'text/xml;charset=UTF-8' }
        });

        // Parsear respuesta Recepción
        const jsonRecepcion = parser.parse(dataRecepcion);
        const respuesta = jsonRecepcion['soap:Envelope']['soap:Body']['ns2:validarComprobanteResponse']['RespuestaRecepcionComprobante'];

        if (respuesta.estado === 'RECIBIDA') {
            // Actualizar BD a RECIBIDA
            await supabase.from('facturas').update({ estado_sri: 'RECIBIDA' }).eq('id', facturaDB.id);

            // Pedir Autorización
            const soapAutorizacion = `
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ec="http://ec.gob.sri.ws.autorizacion">
               <soapenv:Header/>
               <soapenv:Body>
                  <ec:autorizacionComprobante><claveAccesoComprobante>${claveAcceso}</claveAccesoComprobante></ec:autorizacionComprobante>
               </soapenv:Body>
            </soapenv:Envelope>`;

            console.log("Solicitando Autorización...");
            const { data: dataAuth } = await axios.post(urls.autorizacion, soapAutorizacion, {
                headers: { 'Content-Type': 'text/xml;charset=UTF-8' }
            });

            const jsonAuth = parser.parse(dataAuth);
            const respAuth = jsonAuth['soap:Envelope']['soap:Body']['ns2:autorizacionComprobanteResponse']['RespuestaAutorizacionComprobante'];

            // Chequear si se autorizó
            const autorizacion = respAuth.autorizaciones?.autorizacion;
            const objAuth = Array.isArray(autorizacion) ? autorizacion[0] : autorizacion; // Manejar si es array u objeto

            const estadoFinal = objAuth?.estado || 'DESCONOCIDO';
            const xmlAutorizado = objAuth?.comprobante;
            const mensajes = objAuth?.mensajes; // Capturar mensajes de error/advertencia

            // Actualizar BD FINAL
            await supabase.from('facturas').update({
                estado_sri: estadoFinal,
                xml_autorizado: xmlAutorizado,
                mensaje_error: mensajes ? JSON.stringify(mensajes) : null // Guardar error en BD si existe
            }).eq('id', facturaDB.id);

            const resultadoExito = { exito: true, estado: estadoFinal, claveAcceso, xmlAutorizado, mensajes };


            console.log("RETORNANDO EXITO:", resultadoExito.estado);
            return resultadoExito;

        } else {
            // Error en Recepción (ej: Clave duplicada)
            await supabase.from('facturas').update({
                estado_sri: 'DEVUELTA',
                mensaje_error: JSON.stringify(respuesta.comprobantes)
            }).eq('id', facturaDB.id);
            console.log("RETORNANDO ERROR RECEPCION");
            return { exito: false, estado: 'DEVUELTA', error: respuesta };
        }

    } catch (err) {
        console.error("Error de Red/SRI", err);
        console.error("Error de Red/SRI", err);
        return { exito: false, error: err.message };
    }
}

module.exports = { procesarFacturaCompleta };