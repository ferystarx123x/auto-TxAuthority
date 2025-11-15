const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

/**
 * Menghasilkan kunci enkripsi.
 */
function generateConfigKey() {
    return crypto.pbkdf2Sync(
        'FASTARX_CONFIG_KEY_2024',
        'CONFIG_SALT_2024',
        50000,
        32,
        'sha256'
    );
}

/**
 * Mengenkripsi nilai plaintext.
 */
function encryptValue(plainText) {
    if (!plainText) return '';
    
    try {
        const key = generateConfigKey();
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        
        let encrypted = cipher.update(plainText, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        
        return `${encrypted}:${iv.toString('hex')}`;
        
    } catch (error) {
        console.error(`Gagal mengenkripsi nilai: ${error.message}`);
        return '';
    }
}

// Inisialisasi interface readline
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

/**
 * Fungsi utama untuk membuat file .env
 */
async function createEnv() {
    console.log('==============================================');
    console.log('--- Pembuatan File .env Otomatis Penuh ---');
    console.log('==============================================');
    
    // --- Bagian 1: Konfigurasi Keamanan (Hardcoded) ---
    console.log('\n--- Bagian 1: Konfigurasi Keamanan (Otomatis) ---');
    
    // DATA DARI INPUT TERBARU ANDA
    const adminPass = "ferystarx123zxc";
    const scriptPass = "shelomithaay";
    const githubMain = "https://raw.githubusercontent.com/ferystarx7/project-cripto/main/security-config.json";
    const githubBackup = "https://raw.githubusercontent.com/ferystarx/scryty/main/shelo.json";
    const salt = "FASTARX_SECURE_SALT_2024";
    
    console.log(`[OK] Data Keamanan dimuat.`);

    // --- Bagian 2: Konfigurasi Bot Telegram (Hardcoded) ---
    console.log('\n--- Bagian 2: Konfigurasi Telegram (Otomatis) ---');
    
    // BOT TELEGRAM UTAMA (untuk notifikasi transaksi)
    const telegramToken = '8255643248:AAG2WflPJ03flRPBRlfPoOjQ_8Mj74prIiA'; 
    
    // BOT TELEGRAM CONTROLLER BARU (untuk login & kontrol)
    const telegramControllerToken = '7997047144:AAE_tDQDqcnkIe-Z7o59cLPbJG8AsPgRVkw';
    
    console.log(`[OK] TELEGRAM_BOT_TOKEN (Notifikasi) dimuat.`);
    console.log(`[OK] TELEGRAM_CONTROLLER_TOKEN (Login) dimuat.`);
    
    // --- Bagian 3: Nilai Kripto/RPC (Hardcoded) ---
    console.log('\n--- Bagian 3: Nilai WalletConnect & RPC (Otomatis) ---');
    const wcProjectId = '90389c47acff78d74136dc8d58fb757c';
    const rpcUrl = 'https://rpc.hoodi.ethpandaops.io/';
    const rpcChainId = '560048';
    
    console.log(`[OK] Data Kripto dimuat.`);

    console.log('\n... Memproses dan mengenkripsi semua nilai ...');

    // Mengenkripsi semua nilai
    const envData = {
        // === BAGIAN 1: KONFIGURASI KEAMANAN ===
        ADMIN_PASSWORD_ENCRYPTED: encryptValue(adminPass),
        SCRIPT_PASSWORD_ENCRYPTED: encryptValue(scriptPass),
        GITHUB_MAIN_URL_ENCRYPTED: encryptValue(githubMain),
        GITHUB_BACKUP_URL_ENCRYPTED: encryptValue(githubBackup),
        ENCRYPTION_SALT_ENCRYPTED: encryptValue(salt),
        
        // === BAGIAN 2: KONFIGURASI TELEGRAM ===
        // Bot untuk notifikasi transaksi
        TELEGRAM_BOT_TOKEN_ENCRYPTED: encryptValue(telegramToken),
        
        // Bot baru untuk controller & login
        TELEGRAM_CONTROLLER_TOKEN_ENCRYPTED: encryptValue(telegramControllerToken),
        
        // === BAGIAN 3: KONFIGURASI KRIPTO ===
        WALLETCONNECT_PROJECT_ID_ENCRYPTED: encryptValue(wcProjectId),
        DEFAULT_RPC_URL_ENCRYPTED: encryptValue(rpcUrl),
        DEFAULT_RPC_CHAIN_ID_ENCRYPTED: encryptValue(rpcChainId),

        // System ID unik
        SYSTEM_ID: `sys_id_${crypto.randomBytes(16).toString('hex')}`
    };

    // Format konten untuk file .env
    let fileContent = `# File .env ini dihasilkan dan dienkripsi secara OTOMATIS.\n`;
    fileContent += `# Dibuat pada: ${new Date().toISOString()}\n`;
    fileContent += `# PERHATIAN: TELEGRAM_CHAT_ID DIHILANGKAN dan HARUS diinput saat runtime.\n\n`;
    
    fileContent += `# ===================================\n`;
    fileContent += `# KONFIGURASI KEAMANAN\n`;
    fileContent += `# ===================================\n`;
    for (const [key, value] of Object.entries(envData)) {
        if (key.includes('ADMIN') || key.includes('SCRIPT') || key.includes('GITHUB') || key.includes('ENCRYPTION') || key === 'SYSTEM_ID') {
            fileContent += `${key}="${value}"\n`;
        }
    }
    
    fileContent += `\n# ===================================\n`;
    fileContent += `# KONFIGURASI TELEGRAM\n`;
    fileContent += `# ===================================\n`;
    fileContent += `# Bot untuk notifikasi transaksi\n`;
    fileContent += `TELEGRAM_BOT_TOKEN_ENCRYPTED="${envData.TELEGRAM_BOT_TOKEN_ENCRYPTED}"\n\n`;
    fileContent += `# Bot untuk controller & login\n`;
    fileContent += `TELEGRAM_CONTROLLER_TOKEN_ENCRYPTED="${envData.TELEGRAM_CONTROLLER_TOKEN_ENCRYPTED}"\n`;
    
    fileContent += `\n# ===================================\n`;
    fileContent += `# KONFIGURASI KRIPTO & RPC\n`;
    fileContent += `# ===================================\n`;
    for (const [key, value] of Object.entries(envData)) {
        if (key.includes('WALLETCONNECT') || key.includes('RPC')) {
            fileContent += `${key}="${value}"\n`;
        }
    }

    // Menulis file .env
    const envPath = path.join(__dirname, '.env');
    fs.writeFileSync(envPath, fileContent);

    console.log('\n==============================================');
    console.log('✅ SUKSES! File .env baru telah dibuat.');
    console.log('==============================================');
    console.log('\n### 📋 DETAIL KONFIGURASI ###');
    console.log('🔐 Bot Controller (Login): 7997047144:AAE_tDQDqcnkIe-Z7o59cLPbJG8AsPgRVkw');
    console.log('🔔 Bot Notifikasi: 8255643248:AAG2WflPJ03flRPBRlfPoOjQ_8Mj74prIiA');
    console.log('🌐 RPC: https://rpc.hoodi.ethpandaops.io/');
    console.log('⛓️ Chain ID: 560048');
    
    console.log('\n### ⚠️ PERINGATAN PENTING ###');
    console.log('1. Pastikan main.js sudah support 2 bot Telegram');
    console.log('2. Bot Controller untuk login & kontrol');
    console.log('3. Bot Notifikasi untuk alert transaksi');
    console.log('4. Chat ID akan diminta setelah login berhasil');
    console.log('\nJalankan: npm start');

    rl.close();
}

// Jalankan fungsi utama
createEnv().catch(console.error);