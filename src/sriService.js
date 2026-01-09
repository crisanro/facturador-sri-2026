const { create } = require('xmlbuilder2');
const { signInvoiceXml } = require('ec-sri-invoice-signer');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { XMLParser } = require('fast-xml-parser');
const { generarClaveAcceso } = require('./utils');

// Configuración
const PATH_FIRMA = path.join(__dirname, '../firmas/firma.p12');
const PASS_FIRMA = process.env.FIRMA_PASSWORD || 'TuContrasena';

const URLS = {
    pruebas: {
        recepcion: 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl',
        autorizacion: 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl'
    },
    produccion: {
        recepcion: 'https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl',
        autorizacion: 'https://cel.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl'
    }
};

// Instancia del parser para leer respuestas del SRI
const parser = new XMLParser({ ignoreAttributes: false });

async function enviarAlSRI(xmlFirmadoBase64, claveAcceso, ambiente = 'pruebas') {
    const urls = ambiente === 'produccion' ? URLS.produccion : URLS.pruebas;

    // --- 1. ENVÍO A RECEPCIÓN ---
    const soapRecepcion = `
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ec="http://ec.gob.sri.ws.recepcion">
       <soapenv:Header/>
       <soapenv:Body>
          <ec:validarComprobante>
             <xml>${xmlFirmadoBase64}</xml>
          </ec:validarComprobante>
       </soapenv:Body>
    </soapenv:Envelope>`;

    try {
        console.log("--> Enviando a Recepción SRI...");
        const { data: dataRecepcion } = await axios.post(urls.recepcion, soapRecepcion, {
            headers: { 'Content-Type': 'text/xml;charset=UTF-8' }
        });

        // Analizar respuesta
        const jsonRecepcion = parser.parse(dataRecepcion);
        const respuestaRecepcion = jsonRecepcion['soap:Envelope']['soap:Body']['ns2:validarComprobanteResponse']['RespuestaRecepcionComprobante'];

        if (respuestaRecepcion.estado !== 'RECIBIDA') {
            return { exito: false, etapa: 'RECEPCION', detalle: respuestaRecepcion };
        }

        // --- 2. SOLICITUD DE AUTORIZACIÓN ---
        // (A veces el SRI tarda milisegundos, es "Offline" pero casi instantáneo)
        console.log("--> Solicitando Autorización SRI...");

        const soapAutorizacion = `
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ec="http://ec.gob.sri.ws.autorizacion">
           <soapenv:Header/>
           <soapenv:Body>
              <ec:autorizacionComprobante>
                 <claveAccesoComprobante>${claveAcceso}</claveAccesoComprobante>
              </ec:autorizacionComprobante>
           </soapenv:Body>
        </soapenv:Envelope>`;

        const { data: dataAuth } = await axios.post(urls.autorizacion, soapAutorizacion, {
            headers: { 'Content-Type': 'text/xml;charset=UTF-8' }
        });

        const jsonAuth = parser.parse(dataAuth);
        const respuestaAuth = jsonAuth['soap:Envelope']['soap:Body']['ns2:autorizacionComprobanteResponse']['RespuestaAutorizacionComprobante'];

        // Verificar si fue autorizada (puede estar "EN PROCESO" o "NO AUTORIZADO")
        const autorizacion = respuestaAuth.autorizaciones?.autorizacion;
        const estadoFinal = Array.isArray(autorizacion) ? autorizacion[0].estado : autorizacion?.estado;

        if (estadoFinal === 'AUTORIZADO') {
            return { exito: true, etapa: 'AUTORIZACION', detalle: autorizacion };
        } else {
            return { exito: false, etapa: 'AUTORIZACION', detalle: autorizacion };
        }

    } catch (error) {
        console.error("Error de conexión SRI:", error.message);
        return { exito: false, error: error.message };
    }
}

// Función Principal exportada
async function procesarFacturaCompleta(datos) {
    // 1. Generar Clave (Igual que antes)
    const claveAcceso = generarClaveAcceso(
        datos.fechaEmision, '01', datos.emisor.ruc, '1',
        datos.emisor.serie, datos.secuencial
    );

    // 2. Construir XML (Resumido para el ejemplo, usa tu función completa anterior)
    const doc = create({ version: '1.0', encoding: 'UTF-8' })
        .ele('factura', { id: 'comprobante', version: '1.1.0' });

    // ... AQUÍ VA TODA TU LÓGICA DE CONSTRUCCIÓN DE XML DEL PASO ANTERIOR ...
    // (Asegúrate de copiar la lógica de llenado de tags aquí)
    const infoTrib = doc.ele('infoTributaria');
    infoTrib.ele('ambiente').txt('1');
    infoTrib.ele('tipoEmision').txt('1');
    infoTrib.ele('razonSocial').txt(datos.emisor.razonSocial);
    infoTrib.ele('ruc').txt(datos.emisor.ruc);
    infoTrib.ele('claveAcceso').txt(claveAcceso);
    infoTrib.ele('codDoc').txt('01');
    infoTrib.ele('estab').txt(datos.emisor.serie.substring(0, 3));
    infoTrib.ele('ptoEmi').txt(datos.emisor.serie.substring(3, 6));
    infoTrib.ele('secuencial').txt(datos.secuencial);
    infoTrib.ele('dirMatriz').txt(datos.emisor.direccion);

    const infoFac = doc.ele('infoFactura');
    const fechaVisual = datos.fechaEmision.split('-').reverse().join('/');
    infoFac.ele('fechaEmision').txt(fechaVisual);
    infoFac.ele('dirEstablecimiento').txt(datos.emisor.direccion);
    infoFac.ele('obligadoContabilidad').txt('NO');
    infoFac.ele('tipoIdentificacionComprador').txt('05');
    infoFac.ele('razonSocialComprador').txt(datos.cliente.nombre);
    infoFac.ele('identificacionComprador').txt(datos.cliente.identificacion);
    infoFac.ele('totalSinImpuestos').txt(datos.totales.subtotal);
    infoFac.ele('totalDescuento').txt('0.00');

    const totalConImp = infoFac.ele('totalConImpuestos');
    const totalImp = totalConImp.ele('totalImpuesto');
    totalImp.ele('codigo').txt('2');
    totalImp.ele('codigoPorcentaje').txt('2');
    totalImp.ele('baseImponible').txt(datos.totales.subtotal);
    totalImp.ele('valor').txt(datos.totales.iva);

    infoFac.ele('propina').txt('0.00');
    infoFac.ele('importeTotal').txt(datos.totales.total);
    infoFac.ele('moneda').txt('DOLAR');

    const detalles = doc.ele('detalles');
    datos.items.forEach(item => {
        const det = detalles.ele('detalle');
        det.ele('codigoPrincipal').txt(item.codigo);
        det.ele('descripcion').txt(item.nombre);
        det.ele('cantidad').txt(item.cantidad);
        det.ele('precioUnitario').txt(item.precio);
        det.ele('descuento').txt('0.00');
        det.ele('precioTotalSinImpuestos').txt(item.total);
        const imps = det.ele('impuestos');
        const imp = imps.ele('impuesto');
        imp.ele('codigo').txt('2');
        imp.ele('codigoPorcentaje').txt('2');
        imp.ele('tarifa').txt('12');
        imp.ele('baseImponible').txt(item.total);
        imp.ele('valor').txt((item.total * 0.12).toFixed(2));
    });

    const xmlString = doc.end({ prettyPrint: true });

    // 3. FIRMAR
    if (!fs.existsSync(PATH_FIRMA)) throw new Error("Falta archivo .p12");
    const p12Buffer = fs.readFileSync(PATH_FIRMA);
    const xmlFirmado = signInvoiceXml(xmlString, p12Buffer, { pkcs12Password: PASS_FIRMA });

    // 4. ENVIAR AL SRI (Aquí conectamos todo)
    // Convertir a base64 para envío SOAP
    const xmlBase64 = Buffer.from(xmlFirmado).toString('base64');

    const resultadoSRI = await enviarAlSRI(xmlBase64, claveAcceso, 'pruebas');

    return {
        claveAcceso,
        xmlGenerado: xmlFirmado,
        resultadoSRI
    };
}

module.exports = { procesarFacturaCompleta };