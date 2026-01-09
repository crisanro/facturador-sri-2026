// src/calculadoraSri.js

// Mapeo de códigos SRI (Según Ficha Técnica y actualizaciones recientes)
const CODIGOS_IVA = {
    0: { codigo: '2', codigoPorcentaje: '0' }, // 0%
    12: { codigo: '2', codigoPorcentaje: '2' }, // 12%
    15: { codigo: '2', codigoPorcentaje: '4' }, // 15% (Código actual)
    5: { codigo: '2', codigoPorcentaje: '5' }  // 5% (Materiales construcción)
};

/**
 * Recibe items simples y devuelve la estructura compleja del SRI
 * calculando impuestos automáticamente.
 */
function calcularTotalesEImpuestos(items) {
    let totalSinImpuestos = 0;
    let totalDescuento = 0;

    // Acumulador para agrupar impuestos (El XML pide agrupar por tarifa)
    const impuestosAcumulados = {};

    // 1. Procesar cada item
    const detallesXml = items.map(item => {
        const cantidad = parseFloat(item.cantidad);
        const precioUnitario = parseFloat(item.precio); // Precio unitario SIN IVA
        const descuento = item.descuento || 0;

        // Cálculo línea
        const precioTotalSinImpuesto = (cantidad * precioUnitario) - descuento;
        totalSinImpuestos += precioTotalSinImpuesto;
        totalDescuento += descuento;

        // Calcular impuesto de este item
        const tarifa = item.tarifaIva || 0; // Si no envían tarifa, asume 0
        const infoSri = CODIGOS_IVA[tarifa] || CODIGOS_IVA[0];
        const valorImpuesto = precioTotalSinImpuesto * (tarifa / 100);

        // Acumular para el bloque <totalConImpuestos>
        if (!impuestosAcumulados[tarifa]) {
            impuestosAcumulados[tarifa] = {
                codigo: infoSri.codigo,
                codigoPorcentaje: infoSri.codigoPorcentaje,
                baseImponible: 0,
                valor: 0,
                tarifa: tarifa
            };
        }
        impuestosAcumulados[tarifa].baseImponible += precioTotalSinImpuesto;
        impuestosAcumulados[tarifa].valor += valorImpuesto;

        // Retornar estructura para <detalles>
        return {
            codigoPrincipal: item.codigo,
            descripcion: item.nombre,
            cantidad: cantidad.toFixed(2),
            precioUnitario: precioUnitario.toFixed(2),
            descuento: descuento.toFixed(2),
            precioTotalSinImpuesto: precioTotalSinImpuesto.toFixed(2),
            impuestos: [{
                codigo: infoSri.codigo,
                codigoPorcentaje: infoSri.codigoPorcentaje,
                tarifa: tarifa,
                baseImponible: precioTotalSinImpuesto.toFixed(2),
                valor: valorImpuesto.toFixed(2)
            }]
        };
    });

    // 2. Generar bloque <totalConImpuestos>
    const totalConImpuestosXml = Object.values(impuestosAcumulados).map(imp => ({
        codigo: imp.codigo,
        codigoPorcentaje: imp.codigoPorcentaje,
        baseImponible: imp.baseImponible.toFixed(2),
        valor: imp.valor.toFixed(2)
    }));

    // 3. Calcular Importe Total Final
    const totalIvaGeneral = Object.values(impuestosAcumulados).reduce((sum, imp) => sum + imp.valor, 0);
    const importeTotal = totalSinImpuestos + totalIvaGeneral;

    return {
        detallesXml,
        totalConImpuestosXml,
        totales: {
            totalSinImpuestos: totalSinImpuestos.toFixed(2),
            totalDescuento: totalDescuento.toFixed(2),
            importeTotal: importeTotal.toFixed(2),
            totalIva: totalIvaGeneral.toFixed(2)
        }
    };
}

module.exports = { calcularTotalesEImpuestos };