const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.warn("⚠️ Advertencia: SUPABASE_URL o SUPABASE_KEY no están configurados en el .env");
}

const supabase = createClient(supabaseUrl, supabaseKey);

module.exports = { supabase };
