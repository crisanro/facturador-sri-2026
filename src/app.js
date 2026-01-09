const express = require('express');
const cors = require('cors'); // Asegúrate de haber instalado cors
const { procesarFacturaCompleta } = require('./sriService');
require('dotenv').config(); // Cargar variables de entorno locales si existen

const app = express();
app.use(cors());
app.use(express.json());

// Endpoint único y potente
app.post('/api/facturar', async (req, res) => {
    try {
        console.log("--> Nueva solicitud de facturación recibida");
        
        // Ejecutamos toda la lógica encapsulada
        const resultado = await procesarFacturaCompleta(req.body);

        if (resultado.exito && resultado.estado === 'AUTORIZADO') {
            res.status(200).json({
                ok: true,
                mensaje: "Factura Autorizada Exitosamente",
                datos: resultado
            });
        } else {
            res.status(400).json({
                ok: false,
                mensaje: "La factura no fue autorizada",
                detalle: resultado
            });
        }

    } catch (error) {
        console.error("Error crítico:", error);
        res.status(500).json({ 
            ok: false, 
            mensaje: "Error interno del servidor", 
            error: error.message 
        });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Facturador Inteligente listo en puerto ${PORT}`));
