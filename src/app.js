const express = require('express');
const { procesarFacturaCompleta } = require('./sriService');
const app = express();

app.use(express.json());

app.post('/api/facturar', async (req, res) => { // Nota el async
    try {
        console.log("Recibiendo solicitud de facturación...");
        const datosFactura = req.body;

        // Llamada asíncrona que hace TODO
        const resultado = await procesarFacturaCompleta(datosFactura);

        if (resultado.resultadoSRI.exito) {
            res.json({
                ok: true,
                mensaje: "Factura Autorizada por el SRI",
                claveAcceso: resultado.claveAcceso,
                sriResponse: resultado.resultadoSRI.detalle
            });
        } else {
            // El SRI la rechazó o hubo error de conexión
            res.status(400).json({
                ok: false,
                mensaje: "Error en proceso SRI",
                etapa: resultado.resultadoSRI.etapa,
                errores: resultado.resultadoSRI.detalle
            });
        }

    } catch (error) {
        console.error(error);
        res.status(500).json({ ok: false, error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Facturador SRI listo en puerto ${PORT}`));