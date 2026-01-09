const { DateTime } = require("luxon");

// Algoritmo Módulo 11 (Requisito estricto del SRI)
function modulo11(cadena) {
    let suma = 0;
    let factor = 2;
    for (let i = cadena.length - 1; i >= 0; i--) {
        suma += parseInt(cadena.charAt(i)) * factor;
        factor = factor === 7 ? 2 : factor + 1;
    }
    const verificador = 11 - (suma % 11);
    if (verificador === 11) return 0;
    if (verificador === 10) return 1;
    return verificador;
}

function generarClaveAcceso(fecha, tipoComprobante, ruc, ambiente, serie, secuencial) {
    // Formato fecha: DDMMYYYY
    const fechaFormat = DateTime.fromISO(fecha).toFormat('ddMMyyyy');

    // 1: Pruebas, 2: Producción
    const codigoNumerico = "12345678"; // Puede ser aleatorio
    const tipoEmision = "1"; // 1: Normal

    // Armar la cadena de 48 dígitos
    const clave48 =
        fechaFormat +
        tipoComprobante +
        ruc +
        ambiente +
        serie +
        secuencial +
        codigoNumerico +
        tipoEmision;

    // Calcular dígito verificador y concatenar
    const digitoVerificador = modulo11(clave48);
    return clave48 + digitoVerificador;
}

module.exports = { generarClaveAcceso };