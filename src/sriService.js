const { supabase } = require('./supabaseClient');
const { DateTime } = require('luxon');
const forge = require('node-forge');
const { create } = require('xmlbuilder2');
const axios = require('axios');
const { XMLParser } = require('fast-xml-parser');
const { generarClaveAcceso } = require('./utils');
const { calcularTotalesEImpuestos } = require('./calculadoraSri');
const { signInvoiceXmlCustom } = require('./signer');
const { downloadFile, uploadFile } = require('./storageService');

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

/**
 * Procesa la factura completa, firmando y enviando al SRI.
 * @param {Object} inputCliente - Datos de la factura enviados por el cliente
 * @param {Object} emisor - Datos del emisor obtenidos en el Auth Middleware
 */
async function procesarFacturaCompleta(inputCliente, emisor) {
    console.log(`[SRI] Iniciando proceso para RUC: ${emisor.ruc}, Secuencial: ${emisor.secuencial_actual + 1}`);

    // --- 1. SECUENCIAL ---
    const nuevoSecuencial = emisor.secuencial_actual + 1;
    const secuencialStr = nuevoSecuencial.toString().padStart(9, '0');
    // Actualizamos secuencial en Supabase
    await supabase.from('emisores').update({ secuencial_actual: nuevoSecuencial }).eq('id', emisor.id);

    // --- 2. CÁLCULOS ---
    const calculos = calcularTotalesEImpuestos(inputCliente.items);

    // --- 3. GENERAR XML ---
    const hoy = DateTime.now().setZone('America/Guayaquil').toFormat('yyyy-MM-dd');
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
    infoTrib.ele('estab').txt(emisor.establecimiento || '001');
    infoTrib.ele('ptoEmi').txt(emisor.punto_emision || '001');
    infoTrib.ele('secuencial').txt(secuencialStr);
    infoTrib.ele('dirMatriz').txt(emisor.direccion_matriz);

    if (emisor.contribuyente_rimpe) infoTrib.ele('contribuyenteRimpe').txt(emisor.contribuyente_rimpe);
    if (emisor.agente_retencion) infoTrib.ele('agenteRetencion').txt(emisor.agente_retencion);

    // Info Factura
    const infoFac = doc.ele('infoFactura');
    infoFac.ele('fechaEmision').txt(hoy.split('-').reverse().join('/'));
    infoFac.ele('dirEstablecimiento').txt(emisor.direccion_matriz);
    infoFac.ele('obligadoContabilidad').txt(emisor.obligado_contabilidad || 'NO');
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
    if (inputCliente.pagos && inputCliente.pagos.length > 0) {
        inputCliente.pagos.forEach(pagoItem => {
            const p = pagos.ele('pago');
            p.ele('formaPago').txt(pagoItem.formaPago);
            p.ele('total').txt(pagoItem.total.toFixed(2));
            if (pagoItem.plazo) p.ele('plazo').txt(pagoItem.plazo);
            if (pagoItem.unidadTiempo) p.ele('unidadTiempo').txt(pagoItem.unidadTiempo);
        });
    } else {
        pagos.ele('pago').ele('formaPago').txt('01').up().ele('total').txt(calculos.totales.importeTotal);
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

    // --- 4. FIRMAR XML ---
    // Descargamos la firma desde MinIO
    if (!emisor.p12_path) throw new Error("El emisor no tiene configurada una firma (P12) en storage.");

    const [bucket, ...pathParts] = emisor.p12_path.split('/');
    const p12FileName = pathParts.join('/');

    console.log(`[MinIO] Descargando firma: ${p12FileName} desde bucket: ${bucket}`);
    const p12Buffer = await downloadFile(bucket, p12FileName);
    const password = emisor.p12_pass;

    let targetCertBag = null;
    let targetKeyBag = null;

    try {
        const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'));
        const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);
        const safes = p12.safeContent || p12.safeContents;

        safes.forEach(sc => {
            sc.safeBags.forEach(sb => {
                if (sb.type === forge.pki.oids.certBag) {
                    const cert = sb.cert || (sb.attributes && sb.attributes.cert);
                    if (cert) {
                        const ku = cert.getExtension('keyUsage');
                        if (ku && ku.digitalSignature) {
                            targetCertBag = sb;
                        }
                    }
                } else if (sb.type === forge.pki.oids.pkcs8ShroudedKeyBag || sb.type === forge.pki.oids.keyBag) {
                    targetKeyBag = sb;
                }
            });
        });
    } catch (e) {
        throw new Error("Error procesando certificado P12: " + e.message);
    }

    if (!targetCertBag || !targetKeyBag) throw new Error("No se encontró certificado de firma digital válido en el archivo P12.");

    const xmlFirmado = signInvoiceXmlCustom(xmlString, targetCertBag, targetKeyBag);

    // --- 5. GUARDAR XML FIRMADO EN MINIO ---
    const xmlSignedFileName = `signed/${emisor.ruc}/${claveAcceso}.xml`;
    await uploadFile('invoices', xmlSignedFileName, Buffer.from(xmlFirmado), 'text/xml');

    // --- 6. REGISTRAR EN DB (ESTADO: FIRMADO) ---
    const { data: facturaDB } = await supabase.from('invoices').insert({
        emisor_id: emisor.id,
        clave_acceso: claveAcceso,
        xml_path: `invoices/${xmlSignedFileName}`,
        importe_total: calculos.totales.importeTotal,
        estado: 'FIRMADO'
    }).select().single();

    // --- 7. ENVIAR AL SRI ---
    const urls = emisor.ambiente === '2' ? URLS_SRI.produccion : URLS_SRI.pruebas; // '2' es prod
    const xmlBase64 = Buffer.from(xmlFirmado).toString('base64');

    const soapRecepcion = `
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ec="http://ec.gob.sri.ws.recepcion">
       <soapenv:Header/>
       <soapenv:Body>
          <ec:validarComprobante><xml>${xmlBase64}</xml></ec:validarComprobante>
       </soapenv:Body>
    </soapenv:Envelope>`;

    try {
        const { data: dataRecepcion } = await axios.post(urls.recepcion, soapRecepcion, {
            headers: { 'Content-Type': 'text/xml;charset=UTF-8' }
        });

        const jsonRecepcion = parser.parse(dataRecepcion);
        const respuesta = jsonRecepcion['soap:Envelope']['soap:Body']['ns2:validarComprobanteResponse']['RespuestaRecepcionComprobante'];

        if (respuesta.estado === 'RECIBIDA') {
            await supabase.from('invoices').update({ estado: 'RECIBIDA' }).eq('id', facturaDB.id);

            const soapAutorizacion = `
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ec="http://ec.gob.sri.ws.autorizacion">
               <soapenv:Header/>
               <soapenv:Body>
                  <ec:autorizacionComprobante><claveAccesoComprobante>${claveAcceso}</claveAccesoComprobante></ec:autorizacionComprobante>
               </soapenv:Body>
            </soapenv:Envelope>`;

            const { data: dataAuth } = await axios.post(urls.autorizacion, soapAutorizacion, {
                headers: { 'Content-Type': 'text/xml;charset=UTF-8' }
            });

            const jsonAuth = parser.parse(dataAuth);
            const respAuth = jsonAuth['soap:Envelope']['soap:Body']['ns2:autorizacionComprobanteResponse']['RespuestaAutorizacionComprobante'];
            const autorizacion = respAuth.autorizaciones?.autorizacion;
            const objAuth = Array.isArray(autorizacion) ? autorizacion[0] : autorizacion;

            const estadoFinal = objAuth?.estado || 'DESCONOCIDO';
            const xmlAutorizado = objAuth?.comprobante;

            // Si se autorizó, subimos el XML autorizado (que contiene la fecha de autorización) a MinIO
            let xmlPathFinal = facturaDB.xml_path;
            if (xmlAutorizado) {
                const xmlAuthFileName = `authorized/${emisor.ruc}/${claveAcceso}.xml`;
                await uploadFile('invoices', xmlAuthFileName, Buffer.from(xmlAutorizado), 'text/xml');
                xmlPathFinal = `invoices/${xmlAuthFileName}`;
            }

            // Descontar Crédito
            if (estadoFinal === 'AUTORIZADO') {
                await supabase.rpc('descontar_credito', { emisor_uuid: emisor.id });
            }

            await supabase.from('invoices').update({
                estado: estadoFinal,
                xml_path: xmlPathFinal
            }).eq('id', facturaDB.id);

            return { exito: true, estado: estadoFinal, claveAcceso, xmlAutorizado, mensajes: objAuth?.mensajes };

        } else {
            const errorMsg = JSON.stringify(respuesta.comprobantes);
            await supabase.from('invoices').update({ estado: 'DEVUELTA' }).eq('id', facturaDB.id);
            return { exito: false, estado: 'DEVUELTA', error: errorMsg };
        }

    } catch (err) {
        console.error("[SRI ERROR]", err.message);
        return { exito: false, error: err.message };
    }
}

module.exports = { procesarFacturaCompleta };
