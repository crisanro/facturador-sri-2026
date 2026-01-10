const express = require('express');
const cors = require('cors');
const { procesarFacturaCompleta } = require('./sriService');
const { authMiddleware } = require('./middleware/auth');
const { getSignedUrl } = require('./storageService');
const { supabase } = require('./supabaseClient');
require('dotenv').config();

const app = express();
app.use(cors());

// Middleware para JSON (Excepto para Webhooks de Stripe que necesitan el body raw)
app.use((req, res, next) => {
    if (req.originalUrl === '/api/webhook/stripe') {
        next();
    } else {
        express.json()(req, res, next);
    }
});

// --- 1. ENDPOINT DE FACTURACIÓN (PROTEGIDO) ---
app.post('/api/facturar', authMiddleware, async (req, res) => {
    try {
        console.log(`[API] Solicitud de factura para RUC: ${req.emisor.ruc}`);

        const resultado = await procesarFacturaCompleta(req.body, req.emisor);

        if (resultado.exito && resultado.estado === 'AUTORIZADO') {
            res.status(200).json({
                ok: true,
                mensaje: "Factura Autorizada Exitosamente",
                datos: {
                    claveAcceso: resultado.claveAcceso,
                    estado: resultado.estado,
                    mensajes: resultado.mensajes
                },
                creditsRemaining: req.creditsBalance - 1
            });
        } else {
            res.status(400).json({
                ok: false,
                mensaje: "La factura no fue autorizada o fue devuelta",
                detalle: resultado
            });
        }

    } catch (error) {
        console.error("[CRÍTICO] Error en /api/facturar:", error);
        res.status(500).json({
            ok: false,
            mensaje: "Error interno del servidor",
            error: error.message
        });
    }
});

// --- 2. OBTENER INFORMACIÓN PARA PDF (RIDE) ---
app.get('/api/facturas/:claveAcceso/ride', authMiddleware, async (req, res) => {
    try {
        const { claveAcceso } = req.params;

        // 1. Verificar que la factura pertenezca al emisor
        const { data: factura, error } = await supabase
            .from('invoices')
            .select('*')
            .eq('clave_acceso', claveAcceso)
            .eq('emisor_id', req.emisor.id)
            .single();

        if (error || !factura) {
            return res.status(404).json({ ok: false, mensaje: "Factura no encontrada o no pertenece a su usuario" });
        }

        // 2. Generar link temporal al XML para que el frontend lo descargue y procese
        // El path guardado es "invoices/authorized/..."
        const [bucket, ...pathParts] = factura.xml_path.split('/');
        const fileName = pathParts.join('/');

        const urlXml = await getSignedUrl(bucket, fileName);

        // Devolvemos la URL y metadatos para que el frontend genere el PDF
        res.json({
            ok: true,
            data: {
                claveAcceso: factura.clave_acceso,
                total: factura.importe_total,
                estado: factura.estado,
                xmlUrl: urlXml
            }
        });

    } catch (error) {
        res.status(500).json({ ok: false, error: error.message });
    }
});

// --- 3. WEBHOOK DE STRIPE (RECARGA DE CRÉDITOS) ---
app.post('/api/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];

    // Aquí iría la validación de Stripe con stripe.webhooks.constructEvent
    // Por ahora, un placeholder que confirma recepción
    console.log("[Webhook] Stripe event received");
    res.json({ received: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Backend SRI Multi-tenancy listo en puerto ${PORT}`));
