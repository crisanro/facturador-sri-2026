const { createClient } = require('@supabase/supabase-js');
const { create } = require('xmlbuilder2');
const { signInvoiceXml } = require('ec-sri-invoice-signer');
const fs = require('fs');
const path = require('path');
const { generarClaveAcceso } = require('./utils');
const { calcularTotalesEImpuestos } = require('./calculadoraSri'); // <--- NUEVO

// Iniciar Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

async function facturarInteligente(inputCliente) {

    // 1. Obtener datos del Emisor desde la BD (Tu empresa)
    // Asumimos que mandas el RUC del emisor en el input, o usas un ID fijo si es solo para ti
    const { data: emisor, error } = await supabase
        .from('emisores')
        .select('*')
        .eq('ruc', inputCliente.rucEmisor)
        .single();

    if (error || !emisor) throw new Error("Emisor no encontrado en Base de Datos");

    // 2. Gestionar Secuencial (Incrementar en BD)
    const nuevoSecuencialInt = emisor.secuencial_actual + 1;
    // Formatear a 9 dígitos (ej: 000000123)
    const secuencialString = nuevoSecuencialInt.toString().padStart(9, '0');

    // Actualizar BD inmediatamente para reservar el número (Optimista)
    await supabase.from('emisores').update({ secuencial_actual: nuevoSecuencialInt }).eq('id', emisor.id);

    // 3. USAR EL CEREBRO MATEMÁTICO
    // El frontend solo envió items con cantidad, precio y tarifa. Nosotros calculamos todo.
    const calculos = calcularTotalesEImpuestos(inputCliente.items);

    // 4. Generar Clave de Acceso
    const hoy = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    const claveAcceso = generarClaveAcceso(
        hoy,
        '01',
        emisor.ruc,
        emisor.ambiente.toString(),
        '001001', // Asumimos estab 001 pto 001 por ahora (puedes guardarlo en BD también)
        secuencialString
    );

    // 5. Construir XML (Usando los datos calculados)
    const doc = create({ version: '1.0', encoding: 'UTF-8' })
        .ele('factura', { id: 'comprobante', version: '1.1.0' });

    // Info Tributaria
    const infoTrib = doc.ele('infoTributaria');
    infoTrib.ele('ambiente').txt(emisor.ambiente);
    infoTrib.ele('tipoEmision').txt('1');
    infoTrib.ele('razonSocial').txt(emisor.razon_social);
    infoTrib.ele('ruc').txt(emisor.ruc);
    infoTrib.ele('claveAcceso').txt(claveAcceso);
    infoTrib.ele('codDoc').txt('01');
    infoTrib.ele('estab').txt('001');
    infoTrib.ele('ptoEmi').txt('001');
    infoTrib.ele('secuencial').txt(secuencialString);
    infoTrib.ele('dirMatriz').txt(emisor.direccion_matriz);

    // Info Factura
    const infoFac = doc.ele('infoFactura');
    const fechaVisual = hoy.split('-').reverse().join('/'); // DD/MM/YYYY
    infoFac.ele('fechaEmision').txt(fechaVisual);
    infoFac.ele('dirEstablecimiento').txt(emisor.direccion_matriz);
    infoFac.ele('obligadoContabilidad').txt('NO'); // O leer de BD

    // Datos del Cliente (Vienen del input)
    infoFac.ele('tipoIdentificacionComprador').txt(inputCliente.cliente.tipoId); // 04 RUC, 05 Cedula, 07 Consumidor
    infoFac.ele('razonSocialComprador').txt(inputCliente.cliente.razonSocial);
    infoFac.ele('identificacionComprador').txt(inputCliente.cliente.identificacion);

    // Totales CALCULADOS AUTOMÁTICAMENTE
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

    // Pagos
    const pagos = infoFac.ele('pagos');
    const pago = pagos.ele('pago');
    pago.ele('formaPago').txt('20'); // 20: Otros con sistema financiero (Estándar)
    pago.ele('total').txt(calculos.totales.importeTotal);

    // Detalles (Items)
    const detalles = doc.ele('detalles');
    calculos.detallesXml.forEach(item => {
        const det = detalles.ele('detalle');
        det.ele('codigoPrincipal').txt(item.codigoPrincipal);
        det.ele('descripcion').txt(item.descripcion);
        det.ele('cantidad').txt(item.cantidad);
        det.ele('precioUnitario').txt(item.precioUnitario);
        det.ele('descuento').txt(item.descuento);
        det.ele('precioTotalSinImpuestos').txt(item.precioTotalSinImpuesto);

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

    const xmlString = doc.end({ prettyPrint: true });

    // 6. FIRMAR
    // Nota: En un sistema real, el archivo p12 debería estar en un bucket seguro o desencriptarse temporalmente
    const p12Buffer = fs.readFileSync(path.join(__dirname, '../firmas/firma.p12'));
    const xmlFirmado = signInvoiceXml(xmlString, p12Buffer, { pkcs12Password: emisor.firma_password });

    // 7. GUARDAR EN BASE DE DATOS (Antes de enviar al SRI para tener respaldo)
    const { data: facturaGuardada, error: errorDB } = await supabase
        .from('facturas')
        .insert({
            emisor_id: emisor.id,
            clave_acceso: claveAcceso,
            secuencial: secuencialString,
            total_sin_impuestos: calculos.totales.totalSinImpuestos,
            total_iva: calculos.totales.totalIva,
            importe_total: calculos.totales.importeTotal,
            xml_generado: xmlFirmado,
            estado_sri: 'FIRMADO'
        })
        .select()
        .single();

    // 8. Retornar datos para que el controlador envíe al SRI
    return {
        facturaId: facturaGuardada.id,
        claveAcceso,
        xmlFirmado
    };
}

module.exports = { facturarInteligente };