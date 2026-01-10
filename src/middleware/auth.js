const { supabase } = require('../supabaseClient');

/**
 * Middleware para validar el Bearer Token (API Key) y el RUC del emisor.
 */
async function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            ok: false,
            mensaje: "No autorizado: Se requiere Authorization: Bearer <API_KEY>"
        });
    }

    const token = authHeader.split(' ')[1];

    try {
        // 1. Buscar la API Key en Supabase
        const { data: keyData, error: keyError } = await supabase
            .from('api_keys')
            .select('*, emisores(*)')
            .eq('key', token)
            .eq('active', true)
            .single();

        if (keyError || !keyData) {
            return res.status(401).json({
                ok: false,
                mensaje: "API Key inválida o inactiva"
            });
        }

        const emisor = keyData.emisores;

        // 2. Validar que el RUC del JSON coincida con el de la API Key (Seguridad extra)
        // El RUC puede venir en req.body.rucEmisor (según el JSON de ejemplo del usuario)
        const rucEnviado = req.body.rucEmisor;

        if (!rucEnviado) {
            return res.status(400).json({
                ok: false,
                mensaje: "Falta rucEmisor en el cuerpo de la petición"
            });
        }

        if (emisor.ruc !== rucEnviado) {
            return res.status(403).json({
                ok: false,
                mensaje: `Acceso denegado: Esta API Key pertenece al RUC ${emisor.ruc}, pero enviaste el RUC ${rucEnviado}`
            });
        }

        // 3. Verificar Créditos
        const { data: creditsData, error: creditsError } = await supabase
            .from('user_credits')
            .select('balance')
            .eq('emisor_id', emisor.id)
            .single();

        if (creditsError || !creditsData || creditsData.balance <= 0) {
            return res.status(402).json({
                ok: false,
                mensaje: "Créditos insuficientes para realizar esta operación. Por favor recarga tu cuenta."
            });
        }

        // Adjuntar datos al request para uso posterior
        req.emisor = emisor;
        req.creditsBalance = creditsData.balance;

        next();
    } catch (err) {
        console.error("Error en Auth Middleware:", err);
        return res.status(500).json({
            ok: false,
            mensaje: "Error interno en la validación de seguridad"
        });
    }
}

module.exports = { authMiddleware };
