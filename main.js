/**
 * =============================================================================
 * == FA STARX BOT v15.3.0 (UX/Flow Refinement)
 * ==
 * == SCRIPT GABUNGAN
 * ==
 * == PERUBAHAN (v15.3.0):
 * == 1. [FIX] Alur WalletConnect: Tombol 'Ganti/Pilih Wallet' ditambah di menu
 * ==    WalletConnect agar user bisa memilih wallet aktif sebelum konek.
 * == 2. [FIX] 'List Wallet' sekarang menjadi fungsional untuk alur WC.
 * == 3. [FEAT] Fitur 'Buat Wallet Baru' dihapus (CLI & Telegram),
 * ==    fokus hanya pada 'Import Wallet'.
 * =============================================================================
 */

// ===== DEPENDENCIES (GABUNGAN) =====
const { ethers } = require('ethers');
const readline = require('readline');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const dotenv = require('dotenv');
const SignClient = require('@walletconnect/sign-client').default;
const TelegramBot = require('node-telegram-bot-api');

// Load .env file first
dotenv.config();

// ===================================
// == BAGIAN BARU: ENV DECRYPTOR ==
// ===================================

/**
 * @class EnvDecryptor
 * @description Mengelola dekripsi nilai-nilai sensitif dari file .env.
 */
class EnvDecryptor {
    /**
     * @constructor
     * @description Menginisialisasi EnvDecryptor dan menghasilkan kunci konfigurasi.
     */
    constructor() {
        /**
         * @property {Buffer} configKey - Kunci enkripsi yang digunakan untuk dekripsi.
         */
        this.configKey = this.generateConfigKey();
    }

    /**
     * Menghasilkan kunci enkripsi tetap berdasarkan konstanta.
     * @returns {Buffer} Kunci enkripsi 32-byte.
     */
    generateConfigKey() {
        return crypto.pbkdf2Sync(
            'FASTARX_CONFIG_KEY_2024',
            'CONFIG_SALT_2024',
            50000, // Iterasi
            32,    // Panjang kunci (32 byte = 256 bit)
            'sha256'
        );
    }

    /**
     * Mendekripsi nilai yang diambil dari .env.
     * @param {string} encryptedValue - Nilai terenkripsi (format: data_base64:iv_hex).
     * @returns {string|null} Nilai plaintext yang telah didekripsi, or null jika input tidak valid.
     * @throws {Error} Jika dekripsi gagal.
     */
    decryptValue(encryptedValue) {
        if (!encryptedValue) {
            return null;
        }
        try {
            const key = this.configKey;
            const parts = encryptedValue.split(':');
            if (parts.length !== 2) {
                // Jangan error jika nilai kosong, kembalikan null saja
                if (!encryptedValue) return null;
                
                if (!encryptedValue.includes(':') && encryptedValue.length > 20) {
                     // console.warn(`⚠️ Warning: Nilai "${encryptedValue.substring(0, 10)}..." mungkin tidak terenkripsi.`);
                }
                
                throw new Error('Format nilai terenkripsi tidak valid.');
            }
            
            const encryptedData = parts[0];
            const iv = Buffer.from(parts[1], 'hex');
            
            const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
            
            let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (error) {
            console.error(`DECRYPTION FAILED (Value: ${encryptedValue.substring(0, 10)}...): ${error.message}`);
            // Kembalikan null jika gagal dekripsi (mungkin format salah)
            return null;
        }
    }
}

// =======================================
// == BAGIAN BARU: LOAD & DECRYPT CONFIG ==
// =======================================

/**
 * Memuat dan mendekripsi semua konfigurasi rahasia dari process.env
 * @returns {Object} Objek konfigurasi yang berisi nilai-nilai plaintext.
 * @throws {Error} Jika file .env tidak ada atau dekripsi gagal.
 */
function loadConfiguration() {
    console.log('🔒 Memuat konfigurasi terenkripsi...');
    
    // Cek key esensial dari sistem keamanan
    if (!process.env.ADMIN_PASSWORD_ENCRYPTED || !process.env.SYSTEM_ID) {
        console.error('❌ FATAL ERROR: File .env tidak ditemukan atau tidak lengkap (Sistem Keamanan).');
        console.error('Harap jalankan "node keamanan.js" terlebih dahulu.');
        process.exit(1);
    }
    
    // Cek key esensial untuk bot CryptoAutoTx
    if (!process.env.WALLETCONNECT_PROJECT_ID_ENCRYPTED) {
         console.error('❌ FATAL ERROR: File .env tidak lengkap (Bot CryptoAutoTx).');
         console.error('Harap tambahkan WALLETCONNECT_PROJECT_ID_ENCRYPTED, dll.');
        process.exit(1);
    }


    const envDecryptor = new EnvDecryptor();
    const config = {};

    try {
        // Konfigurasi Sistem Keamanan
        config.ADMIN_PASSWORD = envDecryptor.decryptValue(process.env.ADMIN_PASSWORD_ENCRYPTED);
        config.SCRIPT_PASSWORD = envDecryptor.decryptValue(process.env.SCRIPT_PASSWORD_ENCRYPTED);
        config.GITHUB_MAIN_URL = envDecryptor.decryptValue(process.env.GITHUB_MAIN_URL_ENCRYPTED);
        config.GITHUB_BACKUP_URL = envDecryptor.decryptValue(process.env.GITHUB_BACKUP_URL_ENCRYPTED);
        config.ENCRYPTION_SALT = envDecryptor.decryptValue(process.env.ENCRYPTION_SALT_ENCRYPTED);
        
        // Konfigurasi untuk CryptoAutoTx
        config.TELEGRAM_BOT_TOKEN = envDecryptor.decryptValue(process.env.TELEGRAM_BOT_TOKEN_ENCRYPTED);
        config.TELEGRAM_CONTROLLER_TOKEN = envDecryptor.decryptValue(process.env.TELEGRAM_CONTROLLER_TOKEN_ENCRYPTED);

        config.WALLETCONNECT_PROJECT_ID = envDecryptor.decryptValue(process.env.WALLETCONNECT_PROJECT_ID_ENCRYPTED);
        config.DEFAULT_RPC_URL = envDecryptor.decryptValue(process.env.DEFAULT_RPC_URL_ENCRYPTED);
        config.DEFAULT_RPC_CHAIN_ID = parseInt(envDecryptor.decryptValue(process.env.DEFAULT_RPC_CHAIN_ID_ENCRYPTED), 10);
        
        const optionalKeys = ['TELEGRAM_BOT_TOKEN', 'TELEGRAM_CONTROLLER_TOKEN'];

        // Validasi
        for (const key in config) {
            if (!config[key]) {
                if (optionalKeys.includes(key) && !process.env[`${key}_ENCRYPTED`]) {
                    console.log(`ℹ️ Info: Fitur opsional "${key}" tidak dimuat.`);
                    continue; 
                }
                if (key === 'ENCRYPTION_SALT' && !process.env.ENCRYPTION_SALT_ENCRYPTED) continue; 
                
                throw new Error(`Gagal mendekripsi "${key}" dari .env`);
            }
        }
        
        if (isNaN(config.DEFAULT_RPC_CHAIN_ID)) {
             throw new Error(`DEFAULT_RPC_CHAIN_ID bukan angka yang valid.`);
        }

    } catch (error) {
        console.error('❌ FATAL ERROR: Tidak dapat mendekripsi konfigurasi.');
        console.error(error.message);
        process.exit(1);
    }
    
    console.log('✅ Konfigurasi terenkripsi berhasil dimuat.');
    return config;
}

// ===================================
// == UI & INPUT HANDLER
// ===================================

/**
 * @class ModernUI
 * @description Mengelola semua output visual ke terminal.
 */
class ModernUI {
    constructor() {
        this.theme = {
            primary: '\x1b[38;5;51m',
            secondary: '\x1b[38;5;141m',
            success: '\x1b[38;5;46m',
            warning: '\x1b[38;5;214m',
            error: '\x1b[38;5;203m',
            info: '\x1b[38;5;249m',
            accent: '\x1b[38;5;213m',
            reset: '\x1b[0m'
        };
        this.currentLoadingText = '';
        this.loadingInterval = null;
        this.box = {
            tl: '┏', tr: '┓', bl: '┗', br: '┛',
            h: '━', v: '│', 
            lt: '┣', rt: '┫'
        };
        this.width = process.stdout.columns || 80;
        this.boxWidth = 70;
        process.stdout.on('resize', () => {
            this.width = process.stdout.columns || 80;
        });
    }

    stripAnsi(str) {
        if (!str) return '';
        return str.replace(/\x1b\[[0-9;]*m/g, '');
    }

    getCenterPadding(elementWidth) {
        return ' '.repeat(Math.max(0, Math.floor((this.width - elementWidth) / 2)));
    }

    async typewriterEffect(text, delay = 10) {
        process.stdout.write(this.theme.accent);
        const leftPad = this.getCenterPadding(this.stripAnsi(text).length);
        process.stdout.write(leftPad);
        for (let i = 0; i < text.length; i++) {
            process.stdout.write(text[i]);
            if (delay > 0) await this.sleep(delay);
        }
        process.stdout.write(this.theme.reset + '\n');
    }

    async showAnimatedBanner(charDelay = 1, finalWait = 0) {
        console.clear();
        const bannerLines = [
            '╔══════════════════════════════════════════════════════════════════════════════╗',
            '║                                                                              ║',
            '║  ███████╗ █████╗     ███████╗████████╗ █████╗ ██████╗ ██╗  ██╗███████╗      ║',
            '║  ██╔════╝██╔══██╗    ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗╚██╗██╔╝██╔════╝      ║',
            '║  █████╗  ███████║    ███████╗   ██║   ███████║██████╔╝ ╚███╔╝ ███████╗      ║',
            '║  ██╔══╝  ██╔══██║    ╚════██║   ██║   ██╔══██║██╔══██╗ ██╔██╗ ╚════██║      ║',
            '║  ██║     ██║  ██║    ███████║   ██║   ██║  ██║██║  ██║██╔╝ ██╗███████║      ║',
            '║  ╚═╝     ╚═╝  ╚═╝    ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝      ║',
            '║                                                                              ║',
            '║                   🚀 MULTI-CHAIN TRANSFER BOT v15.3 🚀                       ║',
            '║                                                                              ║',
            '╚══════════════════════════════════════════════════════════════════════════════╝'
        ];
        for (const line of bannerLines) {
            await this.typewriterEffect(line, charDelay);
        }
        console.log(this.theme.reset + '\n');
        if (finalWait > 0) await this.sleep(finalWait);
    }
    
    createBox(title, content, type = 'info') {
        const colors = {
            info: this.theme.primary,
            success: this.theme.success,
            warning: this.theme.warning,
            error: this.theme.error
        };
        const color = colors[type] || this.theme.primary;
        const innerWidth = this.boxWidth - 4;
        const leftPad = this.getCenterPadding(this.boxWidth);

        console.log(leftPad + color + this.box.tl + this.box.h.repeat(innerWidth + 2) + this.box.tr + this.theme.reset);
        const cleanTitle = this.stripAnsi(title);
        const titlePadding = ' '.repeat(innerWidth + 1 - cleanTitle.length);
        console.log(leftPad + color + this.box.v + this.theme.reset + ' ' + this.theme.accent + title + this.theme.reset + titlePadding + color + this.box.v + this.theme.reset);
        console.log(leftPad + color + this.box.lt + this.box.h.repeat(innerWidth + 2) + this.box.rt + this.theme.reset);
        const lines = Array.isArray(content) ? content : content.split('\n');
        lines.forEach(line => {
            const cleanLine = this.stripAnsi(line);
            const linePadding = ' '.repeat(Math.max(0, innerWidth + 1 - cleanLine.length));
            console.log(leftPad + color + this.box.v + this.theme.reset + ' ' + line + linePadding + color + this.box.v + this.theme.reset);
        });
        console.log(leftPad + color + this.box.bl + this.box.h.repeat(innerWidth + 2) + this.box.br + this.theme.reset + '\n');
    }

    showNotification(type, message, title = null) {
        const icons = { 
            success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️',
        };
        const titles = {
            success: 'SUCCESS', error: 'ERROR', warning: 'WARNING', info: 'INFO',
        };
        this.stopLoading();
        const notifTitle = title || titles[type];
        const icon = icons[type] || '📢';
        
        if (Array.isArray(title)) {
            this.createBox(`${icon} ${message}`, title, type);
        } else {
            this.createBox(`${icon} ${notifTitle}`, [message], type);
        }
    }

    startLoading(text) {
        this.stopLoading();
        this.currentLoadingText = text;
        const frames = ['⣾', '⣽', '⣻', '⢿', '⣟', '⣯', '⣷'];
        let i = 0;
        const textWidth = this.stripAnsi(text).length + 2;
        const leftPad = this.getCenterPadding(textWidth);
        this.loadingInterval = setInterval(() => {
            process.stdout.write(`\r\x1b[K`);
            process.stdout.write(leftPad + this.theme.secondary + frames[i] + this.theme.reset + ' ' + text);
            i = (i + 1) % frames.length;
        }, 120);
    }

    stopLoading() {
        if (this.loadingInterval) {
            clearInterval(this.loadingInterval);
            this.loadingInterval = null;
            process.stdout.write('\r\x1b[K');
        }
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

/**
 * @class InputHandler
 * @description Mengelola semua input pengguna dari terminal.
 */
class InputHandler {
    /**
     * @constructor
     * @param {readline.Interface} rl - Interface readline yang dibagikan.
     */
    constructor(rl) {
        this.rl = rl;
        this.ui = new ModernUI(); 
    }

    question(prompt) {
        return new Promise((resolve) => {
            if (!this.rl) {
                console.error('FATAL: InputHandler.question dipanggil tanpa readline interface.');
                resolve(''); 
                return;
            }
            
            const boxPadding = this.ui.getCenterPadding(this.ui.boxWidth);
            const leftPad = boxPadding + '  '; 
            const fullPrompt = `\n${leftPad}${this.ui.theme.secondary}» ${prompt}:${this.ui.theme.reset} `;
            this.rl.question(fullPrompt, (answer) => {
                resolve(answer.trim());
            });
        });
    }

    close() {
        // Penutupan ditangani oleh main()
    }
}

// ===================================
// == GITHUB PASSWORD SYNC SYSTEM
// ===================================

/**
 * @class GitHubPasswordSync
 * @description Mengelola seluruh sistem keamanan, login, integritas file,
 * dan validasi GitHub.
 */
class GitHubPasswordSync {
    /**
     * @constructor
     * @param {readline.Interface | null} rl - Interface readline (null jika mode Telegram).
     * @param {string} adminPassword - Password admin
     * ... (parameter lainnya)
     */
    constructor(rl, adminPassword, scriptPassword, mainUrl, backupUrl, salt) {
        this.ui = new ModernUI();
        this.input = new InputHandler(rl);
        
        this.securityFiles = [
            '.security-system-marker', '.secure-backup-marker', '.fastarx-ultra-secure',
            '.system-integrity-check', '.permanent-security', '.admin-password-secure',
            '.github-validation-lock', '.dual-backup-evidence'
        ];
        this.githubSources = [
            { name: "MAIN", url: mainUrl },
            { name: "BACKUP", url: backupUrl }
        ];
        this.adminPassword = adminPassword;
        this.scriptPassword = scriptPassword;
        this.githubStatus = {
            MAIN: { connected: false, password: null },
            BACKUP: { connected: false, password: null }
        };
        this.consensusAchieved = false;
        this.systemLocked = false; 
        this.encryptionConfig = {
            algorithm: 'aes-256-gcm',
            keyIterations: 100000,
            keyLength: 32,
            salt: salt || crypto.randomBytes(16).toString('hex'), 
            digest: 'sha256'
        };
        this.masterKey = this.generateMasterKey();
    }

    generateMasterKey() {
        return crypto.pbkdf2Sync(
            'FASTARX_SECURE_MASTER_KEY_2024',
            this.encryptionConfig.salt,
            this.encryptionConfig.keyIterations,
            this.encryptionConfig.keyLength,
            this.encryptionConfig.digest
        );
    }

    encryptData(plaintext) {
        try {
            const key = this.masterKey;
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv(this.encryptionConfig.algorithm, key, iv);
            let encrypted = cipher.update(plaintext, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            const authTag = cipher.getAuthTag();
            return {
                encrypted: encrypted,
                iv: iv.toString('hex'),
                authTag: authTag.toString('hex'),
                algorithm: this.encryptionConfig.algorithm,
                timestamp: new Date().toISOString()
            };
        } catch (error) { throw new Error('Encryption failed'); }
    }

    decryptData(encryptedData) {
        try {
            const key = this.masterKey;
            const iv = Buffer.from(encryptedData.iv, 'hex');
            const authTag = Buffer.from(encryptedData.authTag, 'hex');
            const decipher = crypto.createDecipheriv(this.encryptionConfig.algorithm, key, iv);
            decipher.setAuthTag(authTag);
            let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (error) { throw new Error('Decryption failed: ' + error.message); }
    }

    async initialize() {
        console.log('🚀 INITIALIZING SECURITY SYSTEM...');
        const fileStatus = this.checkFileStatus();
        if (fileStatus.missing > 0) {
            if (fileStatus.existing === 0) {
                this.ui.showNotification('info', '📁 No security files found. Running first-time setup...');
                await this.createSecurityFiles();
                this.ui.showNotification('warning', '⚠️ Default passwords created. Please log in and change them.');
            } else {
                this.ui.showNotification('error', '🚫 TAMPERING DETECTED! Security file(s) missing. System locked.');
                this.systemLocked = true;
                return;
            }
        } else {
            console.log('✅ Security file integrity check passed.');
        }
        await this.readPasswordsFromFiles();
        const validationResult = await this.validateGitHubSources();
        if (validationResult.validated) {
            this.ui.showNotification('success', '✅ GitHub validation successful!');
        }
        return true;
    }

    async createSecurityFiles() {
        console.log('📁 Creating security files...');
        let createdCount = 0;
        const timestamp = new Date().toISOString();
        for (const file of this.securityFiles) {
            const filePath = path.join(__dirname, file);
            if (!fs.existsSync(filePath)) {
                try {
                    let fileData = {};
                    if (file === '.admin-password-secure') {
                        fileData = { password: this.adminPassword, timestamp: timestamp, type: 'ADMIN_PASSWORD', securityLevel: 'HIGH' };
                    } else {
                        fileData = { password: this.scriptPassword, timestamp: timestamp, type: 'SECURITY_FILE', filePurpose: file, securityLevel: 'HIGH' };
                    }
                    if (file === '.secure-backup-marker' || file === '.system-integrity-check') {
                        fileData = { ...fileData, password: this.adminPassword, timestamp: timestamp, type: 'ADMIN_PASSWORD', isBackup: true };
                    }
                    const encryptedData = this.encryptData(JSON.stringify(fileData));
                    const finalData = { ...encryptedData, metadata: { system: 'FA_STARX_BOT', created: timestamp, version: '1.0' } };
                    fs.writeFileSync(filePath, JSON.stringify(finalData, null, 2));
                    console.log(`✅ Created: ${file}`);
                    createdCount++;
                } catch (error) { console.log(`❌ Failed to create ${file}`); }
            }
        }
        if (createdCount > 0) console.log(`🎯 ${createdCount} security files created`);
    }

    async readPasswordsFromFiles() {
        console.log('🔑 Reading passwords from security files...');
        const adminFiles = ['.admin-password-secure', '.secure-backup-marker', '.system-integrity-check'];
        const scriptFiles = this.securityFiles.filter(f => !adminFiles.includes(f));
        let adminFound = false, scriptFound = false;
        
        for (const file of adminFiles) {
            const filePath = path.join(__dirname, file);
            if (fs.existsSync(filePath)) {
                try {
                    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                    const fileData = JSON.parse(this.decryptData(data));
                    if (fileData.password && fileData.type === 'ADMIN_PASSWORD') {
                        this.adminPassword = fileData.password;
                        adminFound = true;
                        console.log(`🔑 Admin password loaded from: ${file}`);
                        break;
                    }
                } catch (error) { console.log(`⚠️ Failed to read/decrypt ${file}, trying next...`); }
            }
        }
        if (!adminFound) console.log('❌ CRITICAL: Could not load admin password from any source file.');
        
        for (const file of scriptFiles) {
            const filePath = path.join(__dirname, file);
            if (fs.existsSync(filePath)) {
                try {
                    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                    const fileData = JSON.parse(this.decryptData(data));
                    if (fileData.password && fileData.type === 'SECURITY_FILE') {
                        this.scriptPassword = fileData.password;
                        scriptFound = true;
                        console.log(`🔑 Script password loaded from: ${file}`);
                        break;
                    }
                } catch (error) { /* Lanjut */ }
            }
        }
        if (!scriptFound) console.log('❌ Could not load script password from any source file.');
    }

    async validateGitHubSources() {
        this.ui.startLoading('🔍 Validating GitHub sources...');
        try {
            const results = await Promise.allSettled([
                this.fetchGitHubConfig(this.githubSources[0]),
                this.fetchGitHubConfig(this.githubSources[1])
            ]);
            const validResults = [];
            this.ui.stopLoading(); 
            
            results.forEach((result, index) => {
                const source = this.githubSources[index];
                if (result.status === 'fulfilled' && result.value) {
                    this.githubStatus[source.name] = { connected: true, password: result.value };
                    validResults.push(result.value);
                    console.log(`✅ ${source.name}: Connected`);
                } else {
                    this.githubStatus[source.name] = { connected: false, password: null };
                    console.log(`❌ ${source.name}: Offline`);
                }
            });
            
            if (validResults.length === 2 && validResults[0] === validResults[1]) {
                this.consensusAchieved = true;
                this.scriptPassword = validResults[0];
                await this.updateSecurityFilesWithGitHubPassword(validResults[0]);
                return { validated: true, message: 'Dual GitHub validation passed' };
            }
            return { validated: false, message: `GitHub status: ${validResults.length}/2 connected` };
        } catch (error) {
            this.ui.stopLoading();
            return { validated: false, message: 'Validation error' };
        }
    }

    async fetchGitHubConfig(source) {
        return new Promise((resolve, reject) => {
            const url = new URL(source.url);
            const options = {
                hostname: url.hostname, port: 443, path: url.pathname, method: 'GET',
                headers: { 'User-Agent': 'FASTARX-BOT/1.0' },
                timeout: 10000
            };
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => {
                    try {
                        if (res.statusCode === 200) {
                            const config = JSON.parse(data);
                            const password = this.extractPassword(config);
                            if (password) resolve(password);
                            else reject(new Error('No password found in JSON'));
                        } else reject(new Error(`HTTP ${res.statusCode}`));
                    } catch (error) { reject(new Error('Parse error')); }
                });
            });
            req.on('error', reject);
            req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
            req.end();
        });
    }

    extractPassword(config) {
        if (config.scriptPassword) return config.scriptPassword;
        if (config.password) return config.password;
        if (config.security && config.security.password) return config.security.password;
        return null;
    }

    async updateSecurityFilesWithGitHubPassword(newPassword) {
        console.log('🔄 Updating security files with GitHub password...');
        const timestamp = new Date().toISOString();
        const adminFiles = ['.admin-password-secure', '.secure-backup-marker', '.system-integrity-check'];
        for (const file of this.securityFiles) {
            if (adminFiles.includes(file)) continue; 
            const filePath = path.join(__dirname, file);
            try {
                let fileData = {
                    password: newPassword, timestamp: timestamp, type: 'SECURITY_FILE',
                    filePurpose: file, securityLevel: 'GITHUB_VALIDATED', validatedBy: 'DUAL_GITHUB'
                };
                const encryptedData = this.encryptData(JSON.stringify(fileData));
                const finalData = { ...encryptedData, metadata: { system: 'FA_STARX_BOT', created: timestamp, githubValidated: true } };
                fs.writeFileSync(filePath, JSON.stringify(finalData, null, 2));
            } catch (error) { console.log(`❌ Failed to update ${file}`); }
        }
        this.scriptPassword = newPassword;
        console.log('✅ Script password files updated with GitHub password');
    }

    async showLoginOptions() {
        this.ui.createBox('🔐 SECURE LOGIN', [
            'FA STARX BOT SECURITY SYSTEM', '', '🔑 Login Methods:',
            '1. Administrator Access', '2. Script Password Access', '', 'Select login method:'
        ], 'info');
        return await this.input.question('Select option (1-2)');
    }

    async loginWithAdmin() {
        this.ui.createBox('🔐 ADMINISTRATOR LOGIN', [
            'Full System Access', '', '⚠️  Requires admin password', '🔒 Secure authentication', '', 'Enter administrator password:'
        ], 'warning');
        let attempts = 0;
        while (attempts < 3) {
            const inputPassword = await this.input.question('Admin Password');
            if (inputPassword === this.adminPassword) {
                return { success: true, accessLevel: 'admin' };
            } else {
                attempts++;
                const remaining = 3 - attempts;
                if (remaining > 0) this.ui.showNotification('error', `Wrong password. ${remaining} attempts left`);
                else { this.ui.showNotification('error', '🚫 ACCESS DENIED'); return { success: false, accessLevel: 'admin' }; }
            }
        }
        return { success: false, accessLevel: 'admin' };
    }

    async loginWithScript() {
        this.ui.createBox('🔐 SCRIPT LOGIN', [
            'Standard Bot Access', '', '📋 Available Features:', '• Crypto Auto-Tx (WalletConnect)', '', 'Enter script password:'
        ], 'info');
        let attempts = 0;
        while (attempts < 3) {
            const inputPassword = await this.input.question('Script Password');
            if (inputPassword === this.scriptPassword) {
                return { success: true, accessLevel: 'script' };
            } else {
                attempts++;
                const remaining = 3 - attempts;
                if (remaining > 0) this.ui.showNotification('error', `Wrong password. ${remaining} attempts left`);
                else { this.ui.showNotification('error', '🚫 ACCESS DENIED'); return { success: false, accessLevel: 'script' }; }
            }
        }
        return { success: false, accessLevel: 'script' };
    }

    async verifyAccess() {
        if (this.systemLocked) {
            this.ui.showNotification('error', 'System is locked due to file tampering. Exiting.');
            await this.ui.sleep(3000);
            process.exit(1);
        }
        const loginChoice = await this.showLoginOptions();
        if (loginChoice === '1') {
            return await this.loginWithAdmin();
        } else if (loginChoice === '2') {
            return await this.loginWithScript();
        } else {
            this.ui.showNotification('error', 'Invalid selection');
            return await this.verifyAccess();
        }
    }

    checkFileStatus() {
        let existing = 0, missing = 0;
        for (const file of this.securityFiles) {
            if (fs.existsSync(path.join(__dirname, file))) existing++;
            else missing++;
        }
        return { existing, missing };
    }
    
    close() {
        this.input.close();
    }
}


// ===================================
// == APLIKASI UTAMA: CryptoAutoTx
// ===================================

class CryptoAutoTx {
    /**
     * @constructor
     * @param {readline.Interface | null} rl - Interface readline (null jika mode Telegram).
     * @param {Object} secureConfig - Objek konfigurasi yang telah didekripsi
     */
    constructor(rl, secureConfig) {
        this.config = secureConfig; 
        this.rl = rl;
        
        this.wallet = null;
        this.provider = null;
        this.signClient = null;
        this.bot = null; // Ini untuk NOTIFIKASI (opsional)
        this.isConnected = false;
        this.session = null;
        this.walletFile = path.join(__dirname, 'wallets.enc');
        this.rpcFile = path.join(__dirname, 'rpc-config.json');
        this.masterKey = null;
        this.transactionCounts = new Map();
        
        this.currentRpc = this.config.DEFAULT_RPC_URL;
        this.currentChainId = this.config.DEFAULT_RPC_CHAIN_ID;
        this.currentRpcName = 'Default RPC (from .env)';
        
        this.initTelegramBot(); // Inisialisasi bot notifikasi jika ada
        this.loadRpcConfig(); 
    }

    // 🔧 RPC CONFIGURATION SYSTEM
    loadRpcConfig() {
        try {
            if (fs.existsSync(this.rpcFile)) {
                const rpcConfig = JSON.parse(fs.readFileSync(this.rpcFile, 'utf8'));
                this.currentRpc = rpcConfig.currentRpc || this.currentRpc; 
                this.currentChainId = rpcConfig.currentChainId || this.currentChainId;
                this.currentRpcName = rpcConfig.currentRpcName || this.currentRpcName;
                this.savedRpcs = rpcConfig.savedRpcs || this.getDefaultRpcs();
                console.log('🌐 Loaded RPC configuration:', this.currentRpcName);
            } else {
                this.savedRpcs = this.getDefaultRpcs();
                this.saveRpcConfig();
            }
            this.setupProvider();
        } catch (error) {
            console.log('❌ Error loading RPC config, using default:', error.message);
            this.savedRpcs = this.getDefaultRpcs();
            this.setupProvider();
        }
    }

    getDefaultRpcs() {
        const defaultFromEnv = {
            name: 'Default RPC (from .env)',
            rpc: this.config.DEFAULT_RPC_URL,
            chainId: this.config.DEFAULT_RPC_CHAIN_ID
        };

        return {
            'default_env': defaultFromEnv,
            'mainnet': {
                name: 'Ethereum Mainnet',
                rpc: 'https.eth.llamarpc.com',
                chainId: 1
            },
            'bsc': {
                name: 'BNB Smart Chain',
                rpc: 'https://bsc-dataseed.binance.org/',
                chainId: 56
            },
            'polygon': {
                name: 'Polygon Mainnet',
                rpc: 'https://polygon-rpc.com',
                chainId: 137
            }
        };
    }

    saveRpcConfig() {
        try {
            const rpcConfig = {
                currentRpc: this.currentRpc,
                currentChainId: this.currentChainId,
                currentRpcName: this.currentRpcName,
                savedRpcs: this.savedRpcs,
                updatedAt: new Date().toISOString()
            };
            fs.writeFileSync(this.rpcFile, JSON.stringify(rpcConfig, null, 2));
            console.log('💾 RPC configuration saved');
            return true;
        } catch (error) {
            console.log('❌ Error saving RPC config:', error.message);
            return false;
        }
    }

    setupProvider() {
        try {
            this.provider = new ethers.JsonRpcProvider(this.currentRpc);
            console.log(`🌐 Connected to RPC: ${this.currentRpcName}`);
            console.log(`🔗 URL: ${this.currentRpc}`);
            console.log(`⛓️ Chain ID: ${this.currentChainId}`);
            
            if (this.wallet) {
                this.wallet = this.wallet.connect(this.provider);
                console.log('🔄 Wallet reconnected to new RPC');
            }
        } catch (error) {
            console.log('❌ Error setting up provider:', error.message);
            this.currentRpc = this.config.DEFAULT_RPC_URL;
            this.currentChainId = this.config.DEFAULT_RPC_CHAIN_ID;
            this.currentRpcName = 'Default Fallback';
            this.provider = new ethers.JsonRpcProvider(this.currentRpc);
        }
    }

    // 🎛️ RPC MANAGEMENT MENU (CLI)
    async rpcManagementMode() {
        console.log('\n🔧 PENGATURAN RPC');
        console.log('1. Pilih RPC yang tersedia');
        console.log('2. Tambah RPC baru');
        console.log('3. Hapus RPC');
        console.log('4. Lihat RPC saat ini');
        console.log('5. Kembali ke Menu Utama');
        
        const choice = await this.question('Pilih opsi (1-5): ');
        
        switch (choice) {
            case '1': await this.selectRpc(); break;
            case '2': await this.addNewRpc(); break;
            case '3': await this.deleteRpc(); break;
            case '4': await this.showCurrentRpc(); break;
            case '5': return;
            default: console.log('❌ Pilihan tidak valid!');
        }
        await this.rpcManagementMode();
    }

    async selectRpc() {
        console.log('\n📡 PILIH RPC:');
        const rpcList = Object.entries(this.savedRpcs);
        if (rpcList.length === 0) {
            console.log('❌ Tidak ada RPC yang tersimpan');
            return;
        }
        let index = 1;
        for (const [key, rpc] of rpcList) {
            console.log(`${index}. ${rpc.name}`);
            console.log(`   URL: ${rpc.rpc}`);
            console.log(`   Chain ID: ${rpc.chainId}`);
            console.log('-'.repeat(40));
            index++;
        }
        const choice = await this.question(`Pilih RPC (1-${rpcList.length}): `);
        const selectedIndex = parseInt(choice) - 1;
        if (selectedIndex >= 0 && selectedIndex < rpcList.length) {
            const [key, selectedRpc] = rpcList[selectedIndex];
            this.currentRpc = selectedRpc.rpc;
            this.currentChainId = selectedRpc.chainId;
            this.currentRpcName = selectedRpc.name;
            this.setupProvider();
            this.saveRpcConfig();
            console.log(`✅ RPC berhasil diubah ke: ${selectedRpc.name}`);
        } else {
            console.log('❌ Pilihan tidak valid!');
        }
    }

    async addNewRpc() {
        console.log('\n➕ TAMBAH RPC BARU');
        const name = await this.question('Nama RPC (contoh: RPC Sepolia): ');
        const url = await this.question('URL RPC (contoh: https://...): ');
        const chainId = await this.question('Chain ID (contoh: 11155111): ');
        if (!name || !url || !chainId) {
            console.log('❌ Semua field harus diisi!');
            return;
        }
        if (!url.startsWith('http')) {
            console.log('❌ URL harus dimulai dengan http atau https');
            return;
        }
        const chainIdNum = parseInt(chainId);
        if (isNaN(chainIdNum) || chainIdNum <= 0) {
            console.log('❌ Chain ID harus angka positif');
            return;
        }
        console.log('🔄 Testing koneksi RPC...');
        try {
            const testProvider = new ethers.JsonRpcProvider(url);
            const network = await testProvider.getNetwork();
            console.log(`✅ Koneksi berhasil! Chain ID: ${network.chainId}`);
            if (network.chainId !== BigInt(chainIdNum)) {
                console.log(`⚠️ Warning: Chain ID tidak match. Input: ${chainIdNum}, Actual: ${network.chainId}`);
            }
        } catch (error) {
            console.log('❌ Gagal terkoneksi ke RPC:', error.message);
            const continueAnyway = await this.question('Tetap simpan RPC? (y/n): ');
            if (continueAnyway.toLowerCase() !== 'y') return;
        }
        const save = await this.question('Simpan RPC ini? (y/n): ');
        if (save.toLowerCase() === 'y') {
            const key = `custom_${Date.now()}`;
            this.savedRpcs[key] = { name: name, rpc: url, chainId: chainIdNum };
            if (this.saveRpcConfig()) {
                console.log(`✅ RPC "${name}" berhasil disimpan!`);
                const useNow = await this.question('Gunakan RPC ini sekarang? (y/n): ');
                if (useNow.toLowerCase() === 'y') {
                    this.currentRpc = url;
                    this.currentChainId = chainIdNum;
                    this.currentRpcName = name;
                    this.setupProvider();
                    console.log(`✅ Sekarang menggunakan: ${name}`);
                }
            }
        }
    }

    async deleteRpc() {
        console.log('\n🗑️ HAPUS RPC');
        const rpcList = Object.entries(this.savedRpcs);
        if (rpcList.length === 0) {
            console.log('❌ Tidak ada RPC yang tersimpan');
            return;
        }
        let index = 1;
        for (const [key, rpc] of rpcList) {
            console.log(`${index}. ${rpc.name} (${rpc.rpc})`);
            index++;
        }
        const choice = await this.question(`Pilih RPC yang akan dihapus (1-${rpcList.length}): `);
        const selectedIndex = parseInt(choice) - 1;
        if (selectedIndex >= 0 && selectedIndex < rpcList.length) {
            const [key, selectedRpc] = rpcList[selectedIndex];
            if (this.currentRpc === selectedRpc.rpc) {
                console.log('❌ Tidak bisa menghapus RPC yang sedang aktif!');
                return;
            }
            const confirm = await this.question(`Yakin hapus "${selectedRpc.name}"? (y/n): `);
            if (confirm.toLowerCase() === 'y') {
                delete this.savedRpcs[key];
                if (this.saveRpcConfig()) {
                    console.log(`✅ RPC "${selectedRpc.name}" berhasil dihapus!`);
                }
            }
        } else {
            console.log('❌ Pilihan tidak valid!');
        }
    }

    async showCurrentRpc() {
        console.log('\n📊 RPC SAAT INI:');
        console.log(`🏷️ Nama: ${this.currentRpcName}`);
        console.log(`🔗 URL: ${this.currentRpc}`);
        console.log(`⛓️ Chain ID: ${this.currentChainId}`);
        console.log(`💾 Total RPC tersimpan: ${Object.keys(this.savedRpcs).length}`);
    }

    // 🔐 ENCRYPTION SYSTEM (untuk wallets.enc)
    async initializeEncryption() {
        const keyFile = path.join(__dirname, 'master.key');
        try {
            if (fs.existsSync(keyFile)) {
                const keyBase64 = fs.readFileSync(keyFile, 'utf8');
                this.masterKey = Buffer.from(keyBase64, 'base64');
                console.log('🔑 Loaded existing encryption key (master.key)');
            } else {
                this.masterKey = crypto.randomBytes(32);
                fs.writeFileSync(keyFile, this.masterKey.toString('base64'));
                console.log('🔑 Generated new encryption key (master.key)');
                try { fs.chmodSync(keyFile, 0o600); } catch (error) {}
            }
            return true;
        } catch (error) {
            console.log('❌ Error initializing encryption:', error.message);
            return false;
        }
    }

    encrypt(data) {
        try {
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, iv);
            let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
            encrypted += cipher.final('hex');
            const authTag = cipher.getAuthTag();
            return {
                iv: iv.toString('hex'), data: encrypted, authTag: authTag.toString('hex'), version: '2.0'
            };
        } catch (error) {
            console.log('❌ Encryption error:', error.message);
            throw error;
        }
    }

    decrypt(encryptedData) {
        try {
            const iv = Buffer.from(encryptedData.iv, 'hex');
            const authTag = Buffer.from(encryptedData.authTag, 'hex');
            const decipher = crypto.createDecipheriv('aes-256-gcm', this.masterKey, iv);
            decipher.setAuthTag(authTag);
            let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return JSON.parse(decrypted);
        } catch (error) {
            console.log('❌ Decryption error:', error.message);
            throw error;
        }
    }

    // 🔢 Get transaction count from blockchain
    async getTransactionCount(address) {
        try {
            console.log('📊 Getting transaction count from blockchain...');
            const transactionCount = await this.provider.getTransactionCount(address);
            console.log(`📊 Total transaksi di blockchain: ${transactionCount}`);
            return transactionCount;
        } catch (error) {
            console.log('❌ Error getting transaction count:', error.message);
            return 0;
        }
    }

    // 🔢 Get wallet info
    async getWalletInfo(address) {
        try {
            console.log('📈 Getting wallet info from blockchain...');
            const currentBlock = await this.provider.getBlockNumber();
            const txCount = await this.provider.getTransactionCount(address);
            let firstSeen = (txCount > 0) ? `Active (${txCount} tx)` : 'New wallet';
            return { transactionCount: txCount, firstSeen: firstSeen, currentBlock: currentBlock };
        } catch (error) {
            console.log('❌ Error getting wallet info:', error.message);
            return { transactionCount: 0, firstSeen: 'Unknown', currentBlock: 0 };
        }
    }

    // 🔐 WALLET MANAGEMENT
    async loadWallets() {
        try {
            if (!this.masterKey) {
                await this.initializeEncryption();
            }
            if (fs.existsSync(this.walletFile)) {
                const encryptedData = JSON.parse(fs.readFileSync(this.walletFile, 'utf8'));
                if (encryptedData.iv && encryptedData.data && encryptedData.authTag) {
                    const wallets = this.decrypt(encryptedData);
                    console.log('🔓 Loaded encrypted wallets file');
                    return wallets;
                } else {
                    console.log('📄 Loaded plain text wallets file (legacy)');
                    return encryptedData;
                }
            }
        } catch (error) {
            console.log('❌ Error loading wallets, using empty:', error.message);
        }
        return {};
    }

    async saveWallets(wallets) {
        try {
            if (!this.masterKey) {
                await this.initializeEncryption();
            }
            const encryptedData = this.encrypt(wallets);
            fs.writeFileSync(this.walletFile, JSON.stringify(encryptedData, null, 2));
            try { fs.chmodSync(this.walletFile, 0o600); } catch (error) {}
            console.log('🔐 Saved wallets with encryption');
            return true;
        } catch (error) {
            console.log('❌ Encryption failed, saving as plain text:', error.message);
            try {
                const fallbackFile = path.join(__dirname, 'wallets.json');
                fs.writeFileSync(fallbackFile, JSON.stringify(wallets, null, 2));
                console.log('📄 Saved wallets as plain text (fallback)');
                return true;
            } catch (fallbackError) {
                console.log('❌ Fallback save also failed:', fallbackError.message);
                return false;
            }
        }
    }

    async saveWallet(privateKey, nickname = '') {
        try {
            const wallets = await this.loadWallets();
            const wallet = new ethers.Wallet(privateKey);
            const address = wallet.address;
            const txCount = await this.getTransactionCount(address);
            wallets[address] = {
                privateKey: privateKey,
                nickname: nickname || `Wallet_${Object.keys(wallets).length + 1}`,
                createdAt: new Date().toISOString(),
                lastUsed: new Date().toISOString(),
                initialTxCount: txCount
            };
            if (await this.saveWallets(wallets)) {
                console.log(`✅ Wallet disimpan: ${address} (${wallets[address].nickname})`);
                console.log(`📊 Initial transaction count: ${txCount}`);
                return true;
            }
        } catch (error) {
            console.log('❌ Error saving wallet:', error.message);
        }
        return false;
    }

    async listSavedWallets() {
        const wallets = await this.loadWallets();
        if (Object.keys(wallets).length === 0) {
            console.log('📭 Tidak ada wallet yang disimpan');
            return [];
        }
        console.log('\n💼 WALLET YANG DISIMPAN:');
        console.log('='.repeat(60));
        const walletList = [];
        let index = 1;
        for (const [address, data] of Object.entries(wallets)) {
            console.log(`${index}. ${data.nickname}`);
            console.log(`   Address: ${address}`);
            console.log(`   Dibuat: ${new Date(data.createdAt).toLocaleDateString()}`);
            console.log(`   Initial TX: ${data.initialTxCount || 0}`);
            console.log('-'.repeat(40));
            walletList.push({ address, ...data });
            index++;
        }
        return walletList;
    }

    async listWallets(chatId) {
        if (!this.bot) return; // Ini bot notifikasi, bukan controller
        const wallets = await this.loadWallets();
        if (Object.keys(wallets).length === 0) {
            this.bot.sendMessage(chatId, '📭 Tidak ada wallet yang disimpan');
            return;
        }
        let message = '💼 WALLET YANG DISIMPAN:\n\n';
        for (const [address, data] of Object.entries(wallets)) {
            message += `🏷️ ${data.nickname}\n`;
            message += `📍 ${address}\n`;
            message += `📅 ${new Date(data.createdAt).toLocaleDateString()}\n`;
            message += `📊 Initial TX: ${data.initialTxCount || 0}\n\n`;
        }
        this.bot.sendMessage(chatId, message);
    }

    async deleteWallet(address) {
        const wallets = await this.loadWallets();
        if (wallets[address]) {
            
            // [FIX 1 - HAPUS WALLET AKTIF] 
            // Cek jika wallet yang dihapus adalah wallet yang sedang aktif
            if (this.wallet && this.wallet.address.toLowerCase() === address.toLowerCase()) {
                this.wallet = null; // Set wallet aktif ke null
                console.log('ℹ️ Wallet aktif saat ini telah dihapus dan di-deaktivasi.');
            }
            // [END FIX 1]

            delete wallets[address];
            if (await this.saveWallets(wallets)) {
                console.log(`✅ Wallet dihapus: ${address}`);
                return true;
            }
        }
        console.log('❌ Wallet tidak ditemukan');
        return false;
    }

    initTelegramBot() {
        // Ini HANYA untuk notifikasi, BUKAN kontrol
        if (!this.config.TELEGRAM_BOT_TOKEN || !this.config.TELEGRAM_CHAT_ID) {
            console.log('⚠️ Peringatan: Konfigurasi Notifikasi Telegram tidak lengkap. Notifikasi dinonaktifkan.');
            return;
        }
        
        try {
            this.bot = new TelegramBot(this.config.TELEGRAM_BOT_TOKEN, { polling: true });
            console.log('🤖 Telegram Notification Bot initialized');
            this.setupTelegramHandlers();
        } catch (error) {
            console.log('❌ Error initializing Notification bot:', error.message);
        }
    }

    setupTelegramHandlers() {
        if (!this.bot) return; // Safety check

        this.bot.on('message', (msg) => {
            const chatId = msg.chat.id;
            const text = msg.text;
            
            if (chatId.toString() !== this.config.TELEGRAM_CHAT_ID) {
                console.log('⚠️ Unauthorized chat attempt on NOTIFICATION BOT:', chatId);
                return;
            }
            if (text === '/status') this.sendStatus(chatId);
            else if (text === '/start') {
                this.bot.sendMessage(chatId, 
                    '🚀 Crypto Auto Bot - NOTIFICATION CHANNEL\n\n' +
                    'Channel ini hanya untuk notifikasi.\n' +
                    'Gunakan Controller Bot untuk mengelola bot.\n\n' +
                    'Commands:\n' +
                    '/status - Cek status koneksi\n' +
                    '/balance - Cek balance wallet aktif\n' +
                    '/wallets - List wallets tersimpan\n' +
                    '/txstats - Statistik transaksi\n' +
                    '/rpcinfo - Info RPC'
                );
            } else if (text === '/balance' && this.wallet) this.checkBalance(chatId);
            else if (text === '/wallets') this.listWallets(chatId);
            else if (text === '/txstats' && this.wallet) this.getTransactionStats(chatId);
            else if (text === '/rpcinfo') this.sendRpcInfo(chatId);
        });
    }

    sendRpcInfo(chatId) {
        if (!this.bot) return;
        const message = `🌐 RPC INFORMATION\n\n` +
                       `🏷️ Name: ${this.currentRpcName}\n` +
                       `🔗 URL: ${this.currentRpc}\n` +
                       `⛓️ Chain ID: ${this.currentChainId}\n` +
                       `💾 Saved RPCs: ${Object.keys(this.savedRpcs).length}\n` +
                       `🕒 ${new Date().toLocaleString()}`;
        this.bot.sendMessage(chatId, message);
    }

    async getTransactionStats(chatId) {
        if (!this.bot) return;
        if (!this.wallet) {
            this.bot.sendMessage(chatId, '❌ Wallet belum setup!');
            return;
        }
        try {
            this.bot.sendMessage(chatId, '📊 Getting transaction statistics...');
            const walletInfo = await this.getWalletInfo(this.wallet.address);
            const balance = await this.provider.getBalance(this.wallet.address);
            const balanceEth = ethers.formatEther(balance);
            const message = 
                `📊 TRANSACTION STATISTICS\n\n` +
                `💳 ${this.wallet.address}\n` +
                `💰 Balance: ${balanceEth} ETH\n` +
                `📈 Total Transactions: ${walletInfo.transactionCount}\n` +
                `🕒 Status: ${walletInfo.firstSeen}\n` +
                `⛓️ Current Block: ${walletInfo.currentBlock}\n` +
                `🔗 Chain ID: ${this.currentChainId}\n` +
                `🌐 RPC: ${this.currentRpcName}\n` +
                `🕒 ${new Date().toLocaleString()}`;
            this.bot.sendMessage(chatId, message);
        } catch (error) {
            this.bot.sendMessage(chatId, `❌ Error getting stats: ${error.message}`);
        }
    }

    sendStatus(chatId) {
        if (!this.bot) return;
        const status = this.isConnected ? '🟢 TERHUBUNG' : '🔴 TIDAK TERHUBUNG';
        const walletInfo = this.wallet ? `\n💳 Wallet: ${this.wallet.address}` : '\n💳 Wallet: Belum setup';
        const message = `🤖 STATUS BOT (NOTIFIKASI)\n` +
                       `Status: ${status}` +
                       `${walletInfo}\n` +
                       `⛓️ Chain ID: ${this.currentChainId}\n` +
                       `🌐 RPC: ${this.currentRpcName}\n` +
                       `🕒 ${new Date().toLocaleString()}`;
        this.bot.sendMessage(chatId, message);
    }

    question(prompt) {
        if (!this.rl) {
            console.error('FATAL: CryptoAutoTx.question dipanggil tanpa readline interface (mungkin dalam mode Telegram).');
            return Promise.resolve(''); 
        }
        
        return new Promise((resolve) => {
            this.rl.question(prompt, resolve);
        });
    }

    async showMenu() {
        const wallets = await this.loadWallets();
        console.log('\n' + '='.repeat(50));
        console.log('🚀 CRYPTO AUTO TRANSACTION BOT');
        console.log('='.repeat(50));
        console.log('⛓️ Chain ID:', this.currentChainId);
        console.log('🌐 RPC:', this.currentRpcName);
        console.log('🔑 WalletConnect Project:', this.config.WALLETCONNECT_PROJECT_ID.slice(0, 4) + '...');
        console.log('💼 Saved wallets:', Object.keys(wallets).length);
        console.log('💾 Saved RPCs:', Object.keys(this.savedRpcs).length);
        console.log('='.repeat(50));
        console.log('Pilih Mode:');
        console.log('1. Setup Wallet & Connect WalletConnect');
        console.log('2. Cek Balance & Transaction Stats');
        console.log('3. Kelola Wallet');
        console.log('4. Pengaturan RPC');
        console.log('5. Keluar');
        console.log('='.repeat(50));
    }

    // [PERBAIKAN] Hapus "Buat Wallet", ganti nomor
    async walletManagementMode() {
        console.log('\n💼 KELOLA WALLET');
        console.log('1. Gunakan Wallet yang Disimpan');
        console.log('2. Import Wallet Baru');
        console.log('3. Hapus Wallet');
        console.log('4. Kembali ke Menu Utama');
        const choice = await this.question('Pilih opsi (1-4): ');
        switch (choice) {
            case '1': await this.useSavedWallet(); break;
            case '2': await this.importNewWalletCLI(); break;
            case '3': await this.deleteWalletMenu(); break;
            case '4': return;
            default: console.log('❌ Pilihan tidak valid!');
        }
        await this.walletManagementMode();
    }
    
    // [BARU] Fungsi untuk import wallet dari CLI
    async importNewWalletCLI() {
        console.log('\n📥 IMPORT WALLET BARU');
        const privateKey = await this.question('Masukkan private key: ');
        if (!privateKey) {
             console.log('❌ Batal.');
             return;
        }
        
        let tempWallet;
        let pkeyFormatted = privateKey.startsWith('0x') ? privateKey : '0x' + privateKey;
        
        try {
            tempWallet = new ethers.Wallet(pkeyFormatted);
        } catch (e) {
            console.log('❌ Private key tidak valid.');
            return;
        }
        
        console.log(`📍 Address terdeteksi: ${tempWallet.address}`);
        const nickname = await this.question('Beri nama wallet (optional): ');
        
        if (await this.saveWallet(pkeyFormatted, nickname)) {
            console.log(`💾 Wallet berhasil disimpan!`);
        } else {
            console.log(`❌ Gagal menyimpan wallet.`);
        }
    }

    // [DIHAPUS] Fungsi createNewWallet() dihapus

    async useSavedWallet() {
        const walletList = await this.listSavedWallets();
        if (walletList.length === 0) return;
        const choice = await this.question(`Pilih wallet (1-${walletList.length}): `);
        const index = parseInt(choice) - 1;
        if (index >= 0 && index < walletList.length) {
            const selectedWallet = walletList[index];
            console.log(`✅ Memilih wallet: ${selectedWallet.nickname}`);
            console.log(`📍 ${selectedWallet.address}`);
            this.setupWallet(selectedWallet.privateKey);
            const currentTxCount = await this.getTransactionCount(selectedWallet.address);
            const initialTxCount = selectedWallet.initialTxCount || 0;
            const newTransactions = currentTxCount - initialTxCount;
            console.log(`📊 Transaction Stats:`);
            console.log(`   Initial: ${initialTxCount}`);
            console.log(`   Current: ${currentTxCount}`);
            console.log(`   New TX: +${newTransactions}`);
            await this.checkBalance();
            const wallets = await this.loadWallets();
            if (wallets[selectedWallet.address]) {
                wallets[selectedWallet.address].lastUsed = new Date().toISOString();
                await this.saveWallets(wallets);
            }
        } else {
            console.log('❌ Pilihan tidak valid!');
        }
    }

    async deleteWalletMenu() {
        const walletList = await this.listSavedWallets();
        if (walletList.length === 0) return;
        const choice = await this.question(`Pilih wallet yang akan dihapus (1-${walletList.length}): `);
        const index = parseInt(choice) - 1;
        if (index >= 0 && index < walletList.length) {
            const selectedWallet = walletList[index];
            const confirm = await this.question(`Yakin hapus ${selectedWallet.nickname}? (y/n): `);
            if (confirm.toLowerCase() === 'y') {
                await this.deleteWallet(selectedWallet.address);
            }
        } else {
            console.log('❌ Pilihan tidak valid!');
        }
    }

    setupWallet(privateKey) {
        try {
            if (!privateKey.startsWith('0x')) {
                privateKey = '0x' + privateKey;
            }
            this.wallet = new ethers.Wallet(privateKey, this.provider);
            console.log(`✅ Wallet berhasil setup: ${this.wallet.address}`);
            return true;
        } catch (error) {
            console.log('❌ Error setup wallet:', error.message);
            return false;
        }
    }

    // 🔌 WALLETCONNECT METHODS
    async initializeWalletConnect() {
        try {
            console.log('🔄 Initializing WalletConnect...');
            this.signClient = await SignClient.init({
                projectId: this.config.WALLETCONNECT_PROJECT_ID,
                metadata: {
                    name: 'Crypto Auto-Tx Bot',
                    description: 'Bot untuk auto-approve transaksi',
                    url: 'https://github.com/',
                    icons: ['https://avatars.githubusercontent.com/u/37784886']
                }
            });
            console.log('✅ WalletConnect initialized');
            this.setupWalletConnectEvents();
            return true;
        } catch (error) {
            console.log('❌ Error initializing WalletConnect:', error.message);
            return false;
        }
    }

    setupWalletConnectEvents() {
        if (!this.signClient) return;
        this.signClient.on('session_proposal', async (proposal) => {
            console.log('📨 Received session proposal');
            await this.handleSessionProposal(proposal);
        });
        this.signClient.on('session_request', async (request) => {
            console.log('📨 Received session request');
            await this.handleSessionRequest(request);
        });
        this.signClient.on('session_delete', () => {
            console.log('🔌 Session disconnected');
            this.isConnected = false;
            if (this.bot) this.bot.sendMessage(this.config.TELEGRAM_CHAT_ID, '🔴 WALLETCONNECT DISCONNECTED');
        });
        this.signClient.on('session_event', (event) => console.log('📨 Session event received:', event));
        this.signClient.on('session_ping', (ping) => console.log('🏓 Session ping received'));
    }

    async connectWalletConnect(uri) {
        try {
            if (!this.signClient) {
                await this.initializeWalletConnect();
            }
            console.log('🔄 Connecting to WalletConnect URI...');
            let correctedUri = uri;
            if (uri.startsWith('wc:') && !uri.startsWith('walletconnect:')) {
                correctedUri = 'walletconnect:' + uri;
                console.log('🔧 Auto-corrected URI format');
            }
            console.log('📨 Using URI:', correctedUri);
            await this.signClient.pair({ uri: correctedUri });
            console.log('✅ Pairing initiated, menunggu session proposal...');
            return true;
        } catch (error) {
            console.log('❌ Error connecting to WalletConnect:', error.message);
            return false;
        }
    }

    async handleSessionProposal(proposal) {
        try {
            const { id, params } = proposal;
            console.log('🔄 Approving session proposal...');
            const namespaces = {
                eip155: {
                    accounts: [`eip155:${this.currentChainId}:${this.wallet.address}`],
                    methods: [
                        'eth_sendTransaction', 'eth_signTransaction', 'eth_sign',
                        'personal_sign', 'eth_signTypedData', 'eth_signTypedData_v4'
                    ],
                    events: ['chainChanged', 'accountsChanged']
                }
            };
            console.log('Approving with namespaces:', JSON.stringify(namespaces, null, 2));
            const approveResponse = await this.signClient.approve({ id, namespaces });
            this.session = approveResponse;
            this.isConnected = true;
            console.log('✅ Session approved successfully!');
            console.log('Session topic:', this.session.topic);
            if (this.bot) {
                this.bot.sendMessage(this.config.TELEGRAM_CHAT_ID, 
                    `🟢 WALLETCONNECT TERHUBUNG!\n\n` +
                    `💳 ${this.wallet.address}\n` +
                    `⛓️ Chain ${this.currentChainId}\n` +
                    `🌐 RPC: ${this.currentRpcName}\n` +
                    `🤖 Bot siap auto-approve transaksi!`
                );
            }
        } catch (error) {
            console.log('❌ Error approving session:', error.message);
            console.log('Error details:', error);
        }
    }

    async handleSessionRequest(request) {
        try {
            const { id, topic, params } = request;
            const method = params.request?.method;
            console.log('🔄 Handling session request:', method);
            if (method && (method.startsWith('eth_') || method === 'personal_sign' || method === 'eth_signTypedData')) {
                console.log('📨 Transaction request detected');
                await this.handleTransactionRequest(request);
                return;
            }
            await this.signClient.respond({
                topic, response: { id, jsonrpc: '2.0', result: '0x' }
            });
            console.log('✅ Session request approved');
        } catch (error) {
            console.log('❌ Error handling session request:', error.message);
            if (request.topic) {
                try {
                    await this.signClient.respond({
                        topic: request.topic,
                        response: { id: request.id, jsonrpc: '2.0', error: { code: -32000, message: error.message } }
                    });
                } catch (respondError) {
                    console.log('❌ Error responding to session request:', respondError.message);
                }
            }
        }
    }

    bigIntToString(obj) {
        if (obj === null || obj === undefined) return obj;
        if (typeof obj === 'bigint') return obj.toString();
        if (Array.isArray(obj)) return obj.map(item => this.bigIntToString(item));
        if (typeof obj === 'object') {
            const result = {};
            for (const [key, value] of Object.entries(obj)) {
                result[key] = this.bigIntToString(value);
            }
            return result;
        }
        return obj;
    }

    async handleTransactionRequest(request) {
        let method;
        try {
            const { id, topic, params } = request;
            method = params.request?.method;
            console.log('\n' + '🔔'.repeat(20));
            console.log('📨 TRANSAKSI DITERIMA!');
            console.log('Method:', method);
            console.log('Topic:', topic);
            if (!topic) throw new Error('Topic tidak ditemukan dalam request');
            let result;
            switch (method) {
                case 'eth_sendTransaction':
                    console.log('Transaction params:', JSON.stringify(this.bigIntToString(params.request.params[0]), null, 2));
                    result = await this.handleSendTransaction(params.request.params[0]);
                    break;
                case 'eth_signTransaction':
                    console.log('Sign transaction params:', JSON.stringify(this.bigIntToString(params.request.params[0]), null, 2));
                    result = await this.handleSignTransaction(params.request.params[0]);
                    break;
                case 'personal_sign':
                    console.log('Personal sign params:', params.request.params);
                    result = await this.handlePersonalSign(params.request.params);
                    break;
                case 'eth_sign':
                    console.log('Eth sign params:', params.request.params);
                    result = await this.handleEthSign(params.request.params);
                    break;
                case 'eth_signTypedData':
                case 'eth_signTypedData_v4':
                    console.log('Typed data params:', JSON.stringify(this.bigIntToString(params.request.params[1]), null, 2));
                    result = await this.handleSignTypedData(params.request.params);
                    break;
                default:
                    console.log('❌ Method tidak didukung:', method);
                    throw new Error(`Method ${method} tidak didukung`);
            }
            await this.signClient.respond({
                topic, response: { id, jsonrpc: '2.0', result }
            });
            console.log('✅ Transaksi diapprove!');
            const txCount = await this.getTransactionCount(this.wallet.address);
            console.log(`📊 Total transaksi: ${txCount}`);
            console.log('='.repeat(50));
            if (this.bot) {
                this.bot.sendMessage(this.config.TELEGRAM_CHAT_ID,
                    `✅ TRANSAKSI DIAAPPROVE!\n` +
                    `📊 Total Transaksi: ${txCount}\n\n` +
                    `💳 ${this.wallet.address}\n` +
                    `Method: ${method}\n` +
                    `⛓️ Chain: ${this.currentChainId}\n` +
                    `🌐 RPC: ${this.currentRpcName}\n` +
                    `🕒 ${new Date().toLocaleString()}`
                );
            }
        } catch (error) {
            console.log('❌ Error handling transaction:', error.message);
            if (request.topic) {
                try {
                    await this.signClient.respond({
                        topic: request.topic,
                        response: { id: request.id, jsonrpc: '2.0', error: { code: -32000, message: error.message } }
                    });
                } catch (respondError) {
                    console.log('❌ Error responding to transaction request:', respondError.message);
                }
            }
            if (this.bot) {
                this.bot.sendMessage(this.config.TELEGRAM_CHAT_ID,
                    `❌ TRANSAKSI GAGAL!\n\n` +
                    `💳 ${this.wallet.address}\n` +
                    `Method: ${method}\n` +
                    `Error: ${error.message}\n` +
                    `⛓️ Chain: ${this.currentChainId}\n` +
                    `🌐 RPC: ${this.currentRpcName}\n` +
                    `🕒 ${new Date().toLocaleString()}`
                );
            }
        }
    }

    async handleSendTransaction(txParams) {
        console.log('🔄 Handling send transaction...');
        const safeTxParams = { ...txParams };
        if (!safeTxParams.chainId) {
            safeTxParams.chainId = this.currentChainId;
        }
        if (safeTxParams.gasLimit && typeof safeTxParams.gasLimit === 'bigint') {
            safeTxParams.gasLimit = safeTxParams.gasLimit.toString();
        }
        if (safeTxParams.value && typeof safeTxParams.value === 'bigint') {
            safeTxParams.value = safeTxParams.value.toString();
        }
        console.log('🔧 Safe transaction params:', JSON.stringify(this.bigIntToString(safeTxParams), null, 2));
        try {
            console.log('⛽ Estimating gas limit...');
            const estimateParams = { ...safeTxParams };
            if (estimateParams.gasLimit) delete estimateParams.gasLimit;
            const estimatedGas = await this.provider.estimateGas(estimateParams);
            if (estimatedGas) {
                safeTxParams.gasLimit = (estimatedGas * 120n / 100n).toString(); // +20% buffer
                console.log(`⛽ Estimated gas: ${estimatedGas}, using: ${safeTxParams.gasLimit}`);
            } else {
                throw new Error('Gas estimation returned undefined');
            }
        } catch (error) {
            console.log('⚠️ Gas estimation failed, using default:', error.message);
            safeTxParams.gasLimit = (safeTxParams.data && safeTxParams.data !== '0x') ? '100000' : '25000';
            console.log(`⛽ Using default gas: ${safeTxParams.gasLimit}`);
        }
        if (!safeTxParams.gasPrice && !safeTxParams.maxFeePerGas) {
            try {
                const feeData = await this.provider.getFeeData();
                safeTxParams.maxFeePerGas = feeData.maxFeePerGas?.toString();
                safeTxParams.maxPriorityFeePerGas = feeData.maxPriorityFeePerGas?.toString();
                console.log(`⛽ Using maxFeePerGas: ${safeTxParams.maxFeePerGas}`);
            } catch (error) {
                console.log('⚠️ Failed to get fee data, using defaults');
                safeTxParams.gasPrice = '1000000000'; // 1 Gwei
            }
        }
        console.log('📤 Sending transaction with final params:', JSON.stringify(this.bigIntToString(safeTxParams), null, 2));
        try {
            const tx = await this.wallet.sendTransaction(safeTxParams);
            console.log('✅ Transaction sent:', tx.hash);
            this.waitForConfirmation(tx.hash);
            return tx.hash;
        } catch (error) {
            console.log('❌ Error sending transaction:', error.message);
            if (error.message.includes('insufficient funds') || error.code === 'INSUFFICIENT_FUNDS') {
                throw new Error('Saldo tidak cukup untuk melakukan transaksi');
            }
            if (error.message.includes('nonce') || error.code === 'NONCE_EXPIRED') {
                throw new Error('Nonce invalid, coba restart bot');
            }
            throw error;
        }
    }

    async waitForConfirmation(txHash) {
        try {
            console.log('⏳ Waiting for confirmation...');
            const receipt = await this.provider.waitForTransaction(txHash);
            if (receipt.status === 1) console.log('✅ Transaction confirmed in block:', receipt.blockNumber);
            else console.log('❌ Transaction failed in block:', receipt.blockNumber);
            return receipt;
        } catch (error) {
            console.log('⚠️ Error waiting for confirmation:', error.message);
            return null;
        }
    }

    async handleSignTransaction(txParams) {
        console.log('🔄 Handling sign transaction...');
        const safeTxParams = { ...txParams };
        if (!safeTxParams.chainId) safeTxParams.chainId = this.currentChainId;
        if (safeTxParams.gasLimit && typeof safeTxParams.gasLimit === 'bigint') safeTxParams.gasLimit = safeTxParams.gasLimit.toString();
        if (safeTxParams.value && typeof safeTxParams.value === 'bigint') safeTxParams.value = safeTxParams.value.toString();
        const signedTx = await this.wallet.signTransaction(safeTxParams);
        console.log('✅ Transaction signed');
        return signedTx;
    }

    async handlePersonalSign(params) {
        console.log('🔄 Handling personal sign...');
        const [message, address] = params;
        const signedMessage = await this.wallet.signMessage(message);
        console.log('✅ Message signed');
        return signedMessage;
    }

    async handleEthSign(params) {
        console.log('🔄 Handling eth sign...');
        const [address, message] = params;
        const signedMessage = await this.wallet.signMessage(message);
        console.log('✅ Eth sign completed');
        return signedMessage;
    }

    async handleSignTypedData(params) {
        console.log('🔄 Handling typed data sign...');
        const [address, typedData] = params;
        const signedData = await this.wallet.signTypedData(
            typedData.domain, typedData.types, typedData.message
        );
        console.log('✅ Typed data signed');
        return signedData;
    }

    async checkBalance(chatId = null) {
        if (!this.wallet) {
            const msg = '❌ Wallet belum setup!';
            if (chatId && this.bot) this.bot.sendMessage(chatId, msg);
            else if (this.rl) console.log(msg); // Hanya log jika di CLI
            return null; // [Perbaikan] Kembalikan null jika gagal
        }
        try {
            console.log('🔄 Checking balance...');
            const balance = await this.provider.getBalance(this.wallet.address);
            const balanceEth = ethers.formatEther(balance);
            const txCount = await this.getTransactionCount(this.wallet.address);
            
            const message = `💰 BALANCE INFO\n\n` +
                          `Address: ${this.wallet.address}\n` +
                          `Balance: ${balanceEth} ETH\n` +
                          `Total TX: ${txCount}\n` +
                          `Chain: ${this.currentChainId}\n` +
                          `RPC: ${this.currentRpcName}`;
                          
            if (chatId && this.bot) {
                this.bot.sendMessage(chatId, message);
            } else if (this.rl) {
                 // Tampilkan di terminal jika dipanggil dari CLI
                console.log(`💰 Balance: ${balanceEth} ETH`);
                console.log(`💳 Address: ${this.wallet.address}`);
                console.log(`📊 Total Transactions: ${txCount}`);
                console.log(`🌐 RPC: ${this.currentRpcName}`);
            }
            
            return { balance: balanceEth, txCount: txCount };
        } catch (error) {
            console.log('❌ Error checking balance:', error.message);
            if (chatId && this.bot) this.bot.sendMessage(chatId, `❌ Error: ${error.message}`);
            return null;
        }
    }

    async autoTransactionMode() {
        console.log('\n🎯 SETUP WALLET & CONNECT WALLETCONNECT');
        console.log(`🌐 RPC Saat Ini: ${this.currentRpcName}`);
        console.log(`🔗 URL: ${this.currentRpc}`);
        console.log(`⛓️ Chain ID: ${this.currentChainId}`);
        const changeRpc = await this.question('Ganti RPC sebelum lanjut? (y/n): ');
        if (changeRpc.toLowerCase() === 'y') {
            await this.selectRpc();
        }
        await this.initializeEncryption();
        if (!this.wallet) {
            const wallets = await this.loadWallets();
            if (Object.keys(wallets).length > 0) {
                const useSaved = await this.question('Gunakan wallet yang disimpan? (y/n): ');
                if (useSaved.toLowerCase() === 'y') {
                    await this.useSavedWallet();
                    if (!this.wallet) return;
                } else {
                    const privateKey = await this.question('Masukkan private key: ');
                    if (!this.setupWallet(privateKey)) return;
                    const saveWallet = await this.question('Simpan wallet ini? (y/n): ');
                    if (saveWallet.toLowerCase() === 'y') {
                        const nickname = await this.question('Beri nama wallet (optional): ');
                        await this.saveWallet(privateKey, nickname);
                    }
                }
            } else {
                const privateKey = await this.question('Masukkan private key (Wallet tidak tersimpan): ');
                if (!this.setupWallet(privateKey)) return;
                const saveWallet = await this.question('Simpan wallet ini? (y/n): ');
                if (saveWallet.toLowerCase() === 'y') {
                    const nickname = await this.question('Beri nama wallet (optional): ');
                    await this.saveWallet(privateKey, nickname);
                }
            }
        }
        await this.checkBalance();
        console.log('\n📝 Masukkan URI WalletConnect dari web:');
        console.log('Format: wc:... atau walletconnect:wc:...');
        const uri = await this.question('URI: ');
        if (!uri || (!uri.startsWith('wc:') && !uri.startsWith('walletconnect:'))) {
            console.log('❌ URI WalletConnect tidak valid! Harus diawali wc: atau walletconnect:');
            return;
        }
        const connected = await this.connectWalletConnect(uri);
        if (!connected) return;
        console.log('\n' + '🎉'.repeat(20));
        console.log('🤖 BOT AKTIF & STANDBY!');
        console.log('📡 Menunggu transaksi real dari DApp...');
        console.log('💳 Wallet:', this.wallet.address);
        console.log('⛓️ Chain ID:', this.currentChainId);
        console.log('🌐 RPC:', this.currentRpcName);
        console.log('🔑 Project ID:', this.config.WALLETCONNECT_PROJECT_ID.slice(0, 4) + '...');
        console.log('🎉'.repeat(20));
        console.log('\nTekan Ctrl+C untuk keluar');
        
        if (this.bot) {
            this.sendStatus(this.config.TELEGRAM_CHAT_ID);
        }
        this.keepAlive();
    }

    keepAlive() {
        // SIGINT akan ditangani oleh handler global di 'main'
    }

    cleanup() {
        if (this.signClient && this.session) {
            try {
                this.signClient.disconnect({
                    topic: this.session.topic,
                    reason: { code: 6000, message: 'User disconnected' }
                });
            } catch (error) {
                console.log('⚠️ Error disconnecting WalletConnect:', error.message);
            }
        }
        if (this.bot) {
            // Hentikan polling hanya jika ini bot notifikasi (bukan controller)
             if (this.rl) { // Indikator mode CLI
                this.bot.stopPolling();
             }
        }
    }

    async run() {
        try {
            await this.showMenu();
            const choice = await this.question('Pilih mode (1-5): ');
            switch (choice) {
                case '1':
                    await this.autoTransactionMode();
                    break;
                case '2':
                    await this.checkBalance();
                    this.run();
                    break;
                case '3':
                    await this.walletManagementMode();
                    this.run();
                    break;
                case '4':
                    await this.rpcManagementMode();
                    this.run();
                    break;
                case '5':
                    console.log('👋 Keluar...');
                    this.cleanup();
                    this.rl.close();
                    break;
                default:
                    console.log('❌ Pilihan tidak valid!');
                    this.run();
                    break;
            }
        } catch (error) {
            console.log('❌ Error:', error.message);
            this.cleanup();
            if (this.rl) {
                 this.rl.close();
            }
        }
    }
}


// ===================================
// == MAIN EXECUTION (GABUNGAN)
// ===================================

/**
 * @function runTerminalMode
 * @description Fungsi utama aplikasi gabungan (MODE TERMINAL).
 */
async function runTerminalMode(SECURE_CONFIG) {
    let app = null;
    let mainRl = null; 
    const ui = new ModernUI(); 

    try {
        mainRl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        process.on('SIGINT', () => {
            console.log('\n👋 Bot stopped by user (Ctrl+C). Cleaning up...');
            if (app) {
                app.cleanup();
            }
            if (mainRl) {
                mainRl.close();
            }
            process.exit(0);
        });
    
        console.log(ui.getCenterPadding(50) + '🚀 FA STARX BOT - TERMINAL MODE');
        console.log(ui.getCenterPadding(50) + '='.repeat(50));

        const passwordSystem = new GitHubPasswordSync(
            mainRl, 
            SECURE_CONFIG.ADMIN_PASSWORD,
            SECURE_CONFIG.SCRIPT_PASSWORD,
            SECURE_CONFIG.GITHUB_MAIN_URL,
            SECURE_CONFIG.GITHUB_BACKUP_URL,
            SECURE_CONFIG.ENCRYPTION_SALT
        );
        
        await passwordSystem.initialize();

        const loginResult = await passwordSystem.verifyAccess();
        
        if (!loginResult.success) {
            ui.showNotification('error', '❌ Access denied. Exiting...');
            mainRl.close(); 
            process.exit(1);
        }

        if (SECURE_CONFIG.TELEGRAM_BOT_TOKEN) {
            ui.createBox('💬 SETUP TELEGRAM (NOTIFIKASI)', [
                'Token Bot Telegram ditemukan.',
                'Silakan masukkan Chat ID Anda untuk menerima notifikasi.',
                'Kosongkan jika tidak ingin mengaktifkan notifikasi.'
            ], 'info');
            
            const chatId = await passwordSystem.input.question('Telegram Chat ID');
            
            if (chatId) {
                SECURE_CONFIG.TELEGRAM_CHAT_ID = chatId; 
                ui.showNotification('success', '✅ Telegram Chat ID diterima.');
            } else {
                ui.showNotification('warning', '⚠️ Chat ID kosong. Notifikasi Telegram dinonaktifkan.');
            }
        } else {
            console.log('ℹ️ Info: Token Bot Telegram (TELEGRAM_BOT_TOKEN) tidak ditemukan, notifikasi dilewati.');
        }


        ui.createBox('🎉 ACCESS GRANTED', [
            `Welcome, ${loginResult.accessLevel === 'admin' ? 'Administrator' : 'User'}!`,
            '',
            'Loading Crypto Auto-Tx Bot...'
        ], 'success');
        
        await ui.sleep(2000); 
        console.clear(); 

        app = new CryptoAutoTx(mainRl, SECURE_CONFIG);
        await app.run(); 

    } catch (error) {
        console.log(error);
        ui.stopLoading(); 
        ui.showNotification('error', `Application error: ${error.message}`);
        
        if (app) app.cleanup(); 
        if (mainRl) mainRl.close(); 
        process.exit(1);
    }
}
// ===================================
// == TELEGRAM FULL CONTROLLER
// ===================================

class TelegramFullController {
    constructor(secureConfig) {
        this.config = secureConfig;
        this.userStates = new Map();
        this.controllerBot = null;
        this.notificationBot = null; // Bot untuk notifikasi
        this.securitySystem = null;
        this.cryptoApp = null;
        this.isAuthenticated = false;
        this.currentUser = null;
        
        this.initBots();
        this.initSecuritySystem();
    }

    initSecuritySystem() {
        this.securitySystem = new GitHubPasswordSync(
            null, // <-- Penting: null 'rl' karena tidak ada input terminal
            this.config.ADMIN_PASSWORD,
            this.config.SCRIPT_PASSWORD,
            this.config.GITHUB_MAIN_URL,
            this.config.GITHUB_BACKUP_URL,
            this.config.ENCRYPTION_SALT
        );
    }

    initBots() {
        // Controller Bot (untuk semua kontrol)
        if (this.config.TELEGRAM_CONTROLLER_TOKEN) {
            try {
                this.controllerBot = new TelegramBot(this.config.TELEGRAM_CONTROLLER_TOKEN, { polling: true });
                console.log('🎛️ Telegram Full Controller Bot initialized');
                this.setupControllerHandlers();
            } catch (error) {
                console.log('❌ Error initializing Controller Bot:', error.message);
            }
        }

        // Notification Bot (untuk notifikasi transaksi)
        if (this.config.TELEGRAM_BOT_TOKEN) {
             try {
                this.notificationBot = new TelegramBot(this.config.TELEGRAM_BOT_TOKEN);
                console.log('🔔 Telegram Notification Bot ready');
             } catch (error) {
                console.log('❌ Error initializing Notification Bot:', error.message);
             }
        }
    }

    setupControllerHandlers() {
        this.controllerBot.onText(/\/start/, (msg) => this.startSecurityFlow(msg.chat.id));
        this.controllerBot.onText(/\/menu/, (msg) => this.showMainMenu(msg.chat.id));
        this.controllerBot.onText(/\/status/, (msg) => this.sendBotStatus(msg.chat.id));
        
        this.controllerBot.on('message', (msg) => this.handleMessage(msg));
        this.controllerBot.on('callback_query', (query) => this.handleCallback(query));
    }

    // ===================================
    // SECURITY & AUTHENTICATION FLOW
    // ===================================

    async startSecurityFlow(chatId) {
        if (this.isAuthenticated) {
            this.showMainMenu(chatId);
            return;
        }

        await this.securitySystem.initialize();
        this.showLoginOptions(chatId);
    }

    showLoginOptions(chatId) {
        const menu = {
            reply_markup: {
                keyboard: [
                    ['1. Administrator Access'],
                    ['2. Script Password Access']
                ],
                resize_keyboard: true,
                one_time_keyboard: true
            }
        };

        this.controllerBot.sendMessage(chatId,
            `🔐 FA STARX BOT SECURITY SYSTEM\n\n` +
            `🔑 Login Methods:\n` +
            `1. Administrator Access\n` +
            `2. Script Password Access\n\n` +
            `» Select login method:`,
            menu
        );
    }

    async handlePasswordInput(chatId, password, userState, msg) {
        try {
            let isValid = false;
            let accessLevel = '';

            // Hapus pesan password dari chat
            try { await this.controllerBot.deleteMessage(chatId, msg.message_id); } catch(e) {}

            if (userState.action === 'awaiting_admin_password') {
                isValid = (password === this.securitySystem.adminPassword); 
                accessLevel = 'admin';
                userState.attempts = (userState.attempts || 0) + 1;
            } else if (userState.action === 'awaiting_script_password') {
                isValid = (password === this.securitySystem.scriptPassword); 
                accessLevel = 'script';
                userState.attempts = (userState.attempts || 0) + 1;
            }

            if (isValid) {
                this.isAuthenticated = true;
                this.currentUser = { chatId, accessLevel };
                this.userStates.delete(chatId);

                this.controllerBot.sendMessage(chatId,
                    `✅ LOGIN SUCCESSFUL!\n\n` +
                    `Welcome, ${accessLevel === 'admin' ? 'Administrator' : 'User'}!\n\n` +
                    `🔄 Initializing Crypto Auto-Tx Bot...`
                );

                await this.initializeCryptoApp();
                
                if (this.config.TELEGRAM_BOT_TOKEN) {
                    this.requestNotificationChatId(chatId);
                } else {
                     this.controllerBot.sendMessage(chatId, `ℹ️ Info: Token notifikasi (TELEGRAM_BOT_TOKEN) tidak ditemukan. Notifikasi dilewati.`);
                     this.showMainMenu(chatId);
                }

            } else {
                const remainingAttempts = 3 - (userState.attempts || 0);
                if (remainingAttempts > 0) {
                    this.controllerBot.sendMessage(chatId,
                        `❌ Wrong password. ${remainingAttempts} attempts left\n\n` +
                        `» Please try again:`
                    );
                } else {
                    this.controllerBot.sendMessage(chatId, `🚫 ACCESS DENIED - Too many failed attempts.`);
                    this.userStates.delete(chatId);
                }
            }
        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Login error: ${error.message}`);
            this.userStates.delete(chatId);
        }
    }

    async initializeCryptoApp() {
        try {
            this.cryptoApp = new CryptoAutoTx(null, this.config); // <-- null 'rl'
            
            await this.cryptoApp.initializeWalletConnect();
            
            if (this.cryptoApp.signClient) {
                this.cryptoApp.signClient.on('session_proposal', (proposal) => {
                    this.sendNotification(`📨 WalletConnect: Session proposal received`);
                });
                
                this.cryptoApp.signClient.on('session_request', (request) => {
                    const method = request.params.request?.method || 'unknown';
                    this.sendNotification(`📨 WalletConnect: Transaction request received (Method: ${method})`);
                    if (this.currentUser) {
                        this.controllerBot.sendMessage(this.currentUser.chatId, `🔔 NOTIFIKASI: Transaksi diterima (Method: ${method}). Auto-approving...`);
                    }
                });
                 this.cryptoApp.signClient.on('session_delete', () => {
                    this.sendNotification(`🔌 WalletConnect: Session disconnected`);
                    if (this.currentUser) {
                        this.controllerBot.sendMessage(this.currentUser.chatId, `🔌 INFO: WalletConnect session disconnected.`);
                    }
                });
            }

            console.log('✅ Crypto Auto-Tx Bot initialized for Telegram control');
        } catch (error) {
            console.log('❌ Error initializing Crypto App:', error.message);
            if(this.currentUser) this.controllerBot.sendMessage(this.currentUser.chatId, `❌ Error initializing Crypto App: ${error.message}`);
        }
    }

    requestNotificationChatId(chatId) {
        this.userStates.set(chatId, { action: 'awaiting_notification_chat_id' });
        
        this.controllerBot.sendMessage(chatId,
            `💬 NOTIFICATION SETUP\n\n` +
            `Untuk menerima notifikasi transaksi:\n\n` +
            `Kirim Chat ID untuk notifikasi:\n` +
            `(atau ketik 'skip' untuk melewati)`
        );
    }

    async processNotificationChatId(chatId, input) {
        try {
            if (input.toLowerCase() === 'skip') {
                this.controllerBot.sendMessage(chatId, `⏭️ Notifikasi dinonaktifkan.`);
                this.userStates.delete(chatId);
                this.showMainMenu(chatId);
                return;
            }

            const notificationChatId = input.trim();
            
            if (notificationChatId && !isNaN(notificationChatId)) {
                this.config.TELEGRAM_CHAT_ID = notificationChatId;
                
                if (this.config.TELEGRAM_BOT_TOKEN) {
                     if (!this.notificationBot) {
                        this.notificationBot = new TelegramBot(this.config.TELEGRAM_BOT_TOKEN);
                     }
                     // Beri tahu cryptoApp tentang bot notifikasi dan chat ID
                     this.cryptoApp.bot = this.notificationBot;
                     this.cryptoApp.config.TELEGRAM_CHAT_ID = notificationChatId;
                }

                this.controllerBot.sendMessage(chatId,
                    `✅ NOTIFICATION SETUP COMPLETE!\n\n` +
                    `Chat ID: ${notificationChatId}\n` +
                    `Notifikasi transaksi akan aktif.`
                );

                this.sendNotification(`🔔 NOTIFICATION BOT ACTIVATED!\nBot siap menerima notifikasi transaksi.`);

            } else {
                this.controllerBot.sendMessage(chatId, `❌ Invalid Chat ID. Harus angka. Coba lagi atau ketik 'skip':`);
                return;
            }
            
            this.userStates.delete(chatId);
            this.showMainMenu(chatId);

        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Error: ${error.message}`);
        }
    }

    // ===================================
    // MAIN MENU & NAVIGATION
    // ===================================

    showMainMenu(chatId) {
         if (!this.isAuthenticated || chatId !== this.currentUser.chatId) {
             this.controllerBot.sendMessage(chatId, 'Anda harus login. Kirim /start');
             return;
         }
         
        const menu = {
            reply_markup: {
                keyboard: [
                    ['💼 Wallet Management', '📊 Info & Status'],
                    ['🌐 RPC Management', '🔗 WalletConnect'],
                    ['🔐 Logout']
                ],
                resize_keyboard: true,
                one_time_keyboard: false
            }
        };

        this.controllerBot.sendMessage(chatId,
            `🤖 CRYPTO AUTO-TX BOT - MAIN MENU\n\n` +
            `Pilih menu di bawah:\n` +
            `💼 Wallet - Kelola wallet\n` +
            `📊 Info - Balance & status\n` +
            `🌐 RPC - Kelola koneksi\n` +
            `🔗 WC - Connect DApps`,
            menu
        );
    }

    // ===================================
    // WALLET MANAGEMENT
    // ===================================

    // [PERBAIKAN] Hapus "Buat Baru"
    showWalletMenu(chatId) {
         if (!this.isAuthenticated || chatId !== this.currentUser.chatId) return;

        const menu = {
            reply_markup: {
                inline_keyboard: [
                    [
                        { text: '📥 Import Wallet', callback_data: 'wallet_import' },
                        { text: '📋 List/Pilih Wallet', callback_data: 'wallet_list' }
                    ],
                    [
                        { text: '🗑️ Hapus Wallet', callback_data: 'wallet_delete_menu' }
                    ],
                    [
                        { text: '💰 Cek Balance', callback_data: 'wallet_balance' },
                        { text: '📊 TX Stats', callback_data: 'wallet_stats' }
                    ],
                    [
                        { text: '🔙 Main Menu', callback_data: 'main_menu' }
                    ]
                ]
            }
        };

        this.controllerBot.sendMessage(chatId, '💼 WALLET MANAGEMENT:', menu);
    }
    
    async showDeleteWalletMenu(chatId) {
        try {
            const wallets = await this.cryptoApp.loadWallets();
            if (Object.keys(wallets).length === 0) {
                this.controllerBot.sendMessage(chatId, '📭 Tidak ada wallet untuk dihapus.');
                return;
            }

            const buttons = [];
            Object.entries(wallets).forEach(([address, data]) => {
                buttons.push([
                    { 
                        text: `🗑️ ${data.nickname} (${address.slice(0, 6)}...)`, 
                        callback_data: `wallet_delete_confirm_${address}` 
                    }
                ]);
            });
            buttons.push([{ text: '🔙 Batal', callback_data: 'wallet_menu' }]);

            this.controllerBot.sendMessage(chatId, 'Pilih wallet yang akan dihapus:', {
                reply_markup: { inline_keyboard: buttons }
            });
        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Error: ${error.message}`);
        }
    }

    async confirmDeleteWallet(chatId, address) {
         const wallets = await this.cryptoApp.loadWallets();
         const walletData = wallets[address];
         if (!walletData) {
             this.controllerBot.sendMessage(chatId, '❌ Wallet tidak ditemukan.');
             return;
         }

         const menu = {
             reply_markup: {
                 inline_keyboard: [
                     [
                         { text: `🔴 HAPUS ${walletData.nickname}`, callback_data: `wallet_delete_exec_${address}` },
                         { text: '🟢 Batal', callback_data: 'wallet_menu' }
                     ]
                 ]
             }
         };
         // [FIX 3 - PARSING ERROR] Hapus parse_mode
         this.controllerBot.sendMessage(chatId, `Yakin ingin menghapus wallet ${walletData.nickname} (${address})?`, menu);
    }

    async executeDeleteWallet(chatId, address) {
        try {
            const deleted = await this.cryptoApp.deleteWallet(address);
            if (deleted) {
                // [FIX 3 - PARSING ERROR] Hapus parse_mode
                this.controllerBot.sendMessage(chatId, `✅ Wallet (${address}) berhasil dihapus.`);
            } else {
                this.controllerBot.sendMessage(chatId, '❌ Gagal menghapus wallet.');
            }
            this.showWalletMenu(chatId); 
        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Error: ${error.message}`);
        }
    }

    // [DIHAPUS] Fungsi createWallet() dihapus

    async importWalletFlow(chatId) {
        this.userStates.set(chatId, { action: 'awaiting_wallet_import' });
        this.controllerBot.sendMessage(chatId,
            `📥 IMPORT WALLET\n\n` +
            `Kirim private key:\n` +
            `Format: 0x... atau tanpa 0x\n\n` +
            `⚠️ Private key akan dienkripsi dan disimpan aman.`
        );
    }

    async processWalletImport(chatId, privateKey, msg) {
        try {
            // Hapus pesan private key
            try { await this.controllerBot.deleteMessage(chatId, msg.message_id); } catch(e) {}
        
            if (!privateKey.startsWith('0x')) {
                privateKey = '0x' + privateKey;
            }

            const wallet = new ethers.Wallet(privateKey);
            this.userStates.set(chatId, { 
                action: 'awaiting_wallet_name',
                tempData: { privateKey: privateKey, address: wallet.address }
            });

            // [FIX 3 - PARSING ERROR] Hapus parse_mode
            this.controllerBot.sendMessage(chatId,
                `✅ Private Key Valid!\n\n` +
                `📍 Address: ${wallet.address}\n\n` +
                `Sekarang beri nama wallet:`
            );

        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Private Key invalid: ${error.message}`);
            this.userStates.delete(chatId);
        }
    }

    async processWalletName(chatId, walletName) {
        const userState = this.userStates.get(chatId);
        if (!userState?.tempData) {
            this.controllerBot.sendMessage(chatId, '❌ Session expired.');
            return;
        }

        try {
            const { privateKey, address } = userState.tempData;
            const saved = await this.cryptoApp.saveWallet(privateKey, walletName);
            
            if (saved) {
                // [FIX 3 - PARSING ERROR] Hapus parse_mode
                this.controllerBot.sendMessage(chatId,
                    `✅ WALLET BERHASIL DISIMPAN!\n\n` +
                    `🏷️ ${walletName}\n` +
                    `📍 ${address}`
                );

                this.userStates.delete(chatId);
                this.showWalletMenu(chatId);
            }
        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Error: ${error.message}`);
            this.userStates.delete(chatId);
        }
    }

    /**
     * [PERBAIKAN] Modifikasi listWallets untuk menerima prefix callback
     * agar bisa digunakan oleh WalletConnect dan Wallet Management
     */
    async listWallets(chatId, callbackPrefix = 'wallet_select_') {
        try {
            const wallets = await this.cryptoApp.loadWallets();
            
            if (Object.keys(wallets).length === 0) {
                this.controllerBot.sendMessage(chatId, '📭 Tidak ada wallet.');
                return;
            }

            let message = '💼 WALLET YANG DISIMPAN:\n\n';
            const buttons = [];

            Object.entries(wallets).forEach(([address, data], index) => {
                const isActive = this.cryptoApp.wallet?.address?.toLowerCase() === address.toLowerCase();
                
                message += `${isActive ? '🟢 ' : '⚪️ '}${index + 1}. ${data.nickname}\n`;
                message += `   📍 ${address}\n`; // [FIX 3 - PARSING ERROR] Hapus backticks
                message += `   📊 TX: ${data.initialTxCount || 0}\n\n`;

                buttons.push([
                    { 
                        text: `${isActive ? '🟢 ' : ''}${data.nickname}`, 
                        callback_data: `${callbackPrefix}${address}` // Gunakan prefix
                    }
                ]);
            });

            if (callbackPrefix === 'wallet_select_') {
                buttons.push([{ text: '🔙 Kembali', callback_data: 'wallet_menu' }]);
            } else {
                 buttons.push([{ text: '🔙 Batal', callback_data: 'wc_menu' }]); // Kembali ke menu WC
            }

            // [FIX 3 - PARSING ERROR] Hapus parse_mode
            this.controllerBot.sendMessage(chatId, message, {
                reply_markup: { inline_keyboard: buttons }
            });

        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Error: ${error.message}`);
        }
    }

    async selectWallet(chatId, address) {
        try {
            const wallets = await this.cryptoApp.loadWallets();
            const walletData = wallets[address];
            
            if (walletData) {
                const setupSuccess = this.cryptoApp.setupWallet(walletData.privateKey);
                
                if (setupSuccess) {
                    wallets[address].lastUsed = new Date().toISOString();
                    await this.cryptoApp.saveWallets(wallets);

                    // [FIX 3 - PARSING ERROR] Hapus parse_mode
                    this.controllerBot.sendMessage(chatId,
                        `✅ WALLET DIPILIH!\n\n` +
                        `🏷️ ${walletData.nickname}\n` +
                        `📍 ${address}\n\n` +
                        `Wallet aktif dan siap digunakan.`
                    );

                    await this.checkBalance(chatId);
                }
            }
        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Error: ${error.message}`);
        }
    }
    
    async getTransactionStats(chatId) {
        if (!this.cryptoApp.wallet) {
            this.controllerBot.sendMessage(chatId, '❌ Wallet belum setup!');
            return;
        }
        try {
            this.controllerBot.sendMessage(chatId, '📊 Getting transaction statistics...');
            const walletInfo = await this.cryptoApp.getWalletInfo(this.cryptoApp.wallet.address);
            const balance = await this.cryptoApp.provider.getBalance(this.cryptoApp.wallet.address);
            const balanceEth = ethers.formatEther(balance);
            const message = 
                `📊 TRANSACTION STATISTICS\n\n` +
                `💳 ${this.cryptoApp.wallet.address}\n` + // [FIX 3 - PARSING ERROR] Hapus backticks
                `💰 Balance: ${balanceEth} ETH\n` +
                `📈 Total Transactions: ${walletInfo.transactionCount}\n` +
                `🕒 Status: ${walletInfo.firstSeen}\n` +
                `⛓️ Current Block: ${walletInfo.currentBlock}\n` +
                `🔗 Chain ID: ${this.cryptoApp.currentChainId}\n` +
                `🌐 RPC: ${this.cryptoApp.currentRpcName}\n` +
                `🕒 ${new Date().toLocaleString()}`;
            
            // [FIX 3 - PARSING ERROR] Hapus parse_mode
            this.controllerBot.sendMessage(chatId, message);
        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Error getting stats: ${error.message}`);
        }
    }


    // ===================================
    // AUTO TRANSACTION MODE (WalletConnect)
    // ===================================

    // [PERBAIKAN] Tampilkan wallet aktif dan tambahkan tombol 'Ganti Wallet'
    showWalletConnectMenu(chatId) {
         if (!this.isAuthenticated || chatId !== this.currentUser.chatId) return;
         
        const status = this.cryptoApp.isConnected ? '🟢 TERHUBUNG' : '🔴 TIDAK TERHUBUNG';
        const walletInfo = this.cryptoApp.wallet ? 
            `🟢 Aktif: ${this.cryptoApp.wallet.address}` :  // [FIX 3 - PARSING ERROR] Hapus backticks
            '🔴 Belum ada wallet aktif';
        
        const menu = {
            reply_markup: {
                inline_keyboard: [
                    [
                        { text: '🔄 Ganti/Pilih Wallet', callback_data: 'wc_select_wallet' }
                    ],
                    [
                        { text: '🔗 Connect WC', callback_data: 'wc_connect' },
                        { text: '🔄 Status', callback_data: 'wc_status' }
                    ],
                    [
                        { text: '🔌 Disconnect', callback_data: 'wc_disconnect' },
                    ],
                    [
                        { text: '🔙 Main Menu', callback_data: 'main_menu' }
                    ]
                ]
            }
        };

        // [FIX 3 - PARSING ERROR] Hapus parse_mode
        this.controllerBot.sendMessage(chatId,
            `🔗 WALLETCONNECT\n\n` +
            `Status: ${status}\n` +
            `Wallet: ${walletInfo}\n` +
            `Chain: ${this.cryptoApp.currentChainId}`,
            menu
        );
    }

    // [PERBAIKAN] Cek wallet sebelum bertanya URI
    async startWalletConnect(chatId) {
        if (!this.cryptoApp.wallet) {
            this.controllerBot.sendMessage(chatId, '❌ Belum ada wallet aktif. Silakan pilih wallet dulu menggunakan tombol "🔄 Ganti/Pilih Wallet".');
            return;
        }

        this.userStates.set(chatId, { action: 'awaiting_wc_uri' });
        
        // [FIX 3 - PARSING ERROR] Hapus parse_mode
        this.controllerBot.sendMessage(chatId,
            `🔗 WALLETCONNECT SETUP\n\n` +
            `Wallet Aktif: ${this.cryptoApp.wallet.address}\n\n` + // [FIX 3 - PARSING ERROR] Hapus backticks
            `1. Buka DApp di browser\n` +
            `2. Pilih WalletConnect\n` +
            `3. Copy URI\n` +
            `4. Kirim URI ke sini:\n`
        );
    }

    async processWalletConnectURI(chatId, uri, msg) {
        try {
            // Hapus pesan URI
            try { await this.controllerBot.deleteMessage(chatId, msg.message_id); } catch(e) {}
        
            this.controllerBot.sendMessage(chatId, '🔄 Menghubungkan ke WalletConnect...');
            
            const connected = await this.cryptoApp.connectWalletConnect(uri);
            
            if (connected) {
                this.controllerBot.sendMessage(chatId,
                    `✅ PAIRING DIMULAI!\n\n` +
                    `Bot menunggu proposal dari DApp...`
                );
                
                 this.cryptoApp.signClient.once('session_proposal', () => {
                     // [FIX 3 - PARSING ERROR] Hapus parse_mode
                     this.controllerBot.sendMessage(chatId,
                        `🟢 WALLETCONNECT TERHUBUNG!\n\n` +
                        `🤖 Bot standby - siap auto-approve transaksi!\n\n` +
                        `💳 ${this.cryptoApp.wallet.address}\n` + // [FIX 3 - PARSING ERROR] Hapus backticks
                        `⛓️ Chain: ${this.cryptoApp.currentChainId}\n` +
                        `🌐 RPC: ${this.cryptoApp.currentRpcName}`
                     );
                     
                     this.sendNotification(`🔗 WALLETCONNECT CONNECTED!\nDApp terhubung - siap auto-approve.`);
                 });


            } else {
                this.controllerBot.sendMessage(chatId, '❌ Gagal memulai pairing. Cek URI.');
            }

            this.userStates.delete(chatId);
        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Error: ${error.message}`);
            this.userStates.delete(chatId);
        }
    }

    // ===================================
    // RPC MANAGEMENT
    // ===================================

    showRpcMenu(chatId) {
         if (!this.isAuthenticated || chatId !== this.currentUser.chatId) return;

        const menu = {
            reply_markup: {
                inline_keyboard: [
                    [
                        { text: '📡 Pilih RPC', callback_data: 'rpc_select' },
                        { text: '➕ Tambah RPC', callback_data: 'rpc_add' }
                    ],
                    [
                        { text: '🗑️ Hapus RPC', callback_data: 'rpc_delete_menu' },
                        { text: 'ℹ️ Info RPC', callback_data: 'rpc_info' }
                    ],
                    [
                        { text: '🔙 Main Menu', callback_data: 'main_menu' }
                    ]
                ]
            }
        };

        this.controllerBot.sendMessage(chatId, '🌐 RPC MANAGEMENT:', menu);
    }
    
    async showRpcInfo(chatId) {
         this.controllerBot.sendMessage(chatId,
            `ℹ️ INFORMASI RPC SAAT INI\n\n` +
            `🏷️ Nama: ${this.cryptoApp.currentRpcName}\n` +
            `🔗 URL: ${this.cryptoApp.currentRpc}\n` +
            `⛓️ Chain: ${this.cryptoApp.currentChainId}`
        );
    }
    
    async startAddRpcFlow(chatId, step = 1, data = {}) {
        this.userStates.set(chatId, { action: 'awaiting_rpc_add', step, data });
        
        if (step === 1) {
            this.controllerBot.sendMessage(chatId, '➕ TAMBAH RPC (1/3)\n\Kirim Nama RPC (contoh: RPC Sepolia):');
        } else if (step === 2) {
            this.controllerBot.sendMessage(chatId, '➕ TAMBAH RPC (2/3)\n\Kirim URL RPC (contoh: https://...):');
        } else if (step === 3) {
            this.controllerBot.sendMessage(chatId, '➕ TAMBAH RPC (3/3)\n\Kirim Chain ID (contoh: 11155111):');
        }
    }
    
    async processAddRpc(chatId, input, userState) {
        const { step, data } = userState;
        
        try {
            if (step === 1) {
                data.name = input;
                await this.startAddRpcFlow(chatId, 2, data);
            } else if (step === 2) {
                 if (!input.startsWith('http')) {
                    this.controllerBot.sendMessage(chatId, '❌ URL tidak valid. Harus dimulai http/https. Coba lagi:');
                    return;
                 }
                data.url = input;
                await this.startAddRpcFlow(chatId, 3, data);
            } else if (step === 3) {
                 const chainIdNum = parseInt(input);
                 if (isNaN(chainIdNum) || chainIdNum <= 0) {
                    this.controllerBot.sendMessage(chatId, '❌ Chain ID tidak valid. Harus angka positif. Coba lagi:');
                    return;
                 }
                data.chainId = chainIdNum;
                
                const key = `custom_${Date.now()}`;
                this.cryptoApp.savedRpcs[key] = { name: data.name, rpc: data.url, chainId: data.chainId };
                
                if (this.cryptoApp.saveRpcConfig()) {
                    this.controllerBot.sendMessage(chatId, `✅ RPC "${data.name}" berhasil disimpan!`);
                    this.userStates.delete(chatId);
                    this.showRpcMenu(chatId);
                } else {
                     this.controllerBot.sendMessage(chatId, `❌ Gagal menyimpan RPC.`);
                     this.userStates.delete(chatId);
                }
            }
        } catch (error) {
             this.controllerBot.sendMessage(chatId, `❌ Error: ${error.message}`);
             this.userStates.delete(chatId);
        }
    }
    
    async showDeleteRpcMenu(chatId) {
        try {
            const rpcList = Object.entries(this.cryptoApp.savedRpcs);
            if (rpcList.length === 0) {
                this.controllerBot.sendMessage(chatId, '📭 Tidak ada RPC untuk dihapus.');
                return;
            }

            const buttons = [];
            rpcList.forEach(([key, rpc]) => {
                if (this.cryptoApp.currentRpc === rpc.rpc) {
                     buttons.push([ { text: `🟢 ${rpc.name} (Aktif)`, callback_data: 'rpc_delete_active' } ]);
                } else {
                    buttons.push([
                        { 
                            text: `🗑️ ${rpc.name}`, 
                            callback_data: `rpc_delete_exec_${key}` 
                        }
                    ]);
                }
            });
            buttons.push([{ text: '🔙 Batal', callback_data: 'rpc_menu' }]);

            this.controllerBot.sendMessage(chatId, 'Pilih RPC yang akan dihapus:', {
                reply_markup: { inline_keyboard: buttons }
            });
        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Error: ${error.message}`);
        }
    }
    
    async executeDeleteRpc(chatId, rpcKey) {
         try {
             const rpcData = this.cryptoApp.savedRpcs[rpcKey];
             if (!rpcData) {
                 this.controllerBot.sendMessage(chatId, '❌ RPC tidak ditemukan.');
                 return;
             }
             
             delete this.cryptoApp.savedRpcs[rpcKey];
             if (this.cryptoApp.saveRpcConfig()) {
                this.controllerBot.sendMessage(chatId, `✅ RPC "${rpcData.name}" berhasil dihapus!`);
             }
             
             this.showRpcMenu(chatId);
         } catch (error) {
             this.controllerBot.sendMessage(chatId, `❌ Error: ${error.message}`);
         }
    }


    async showRpcList(chatId) {
        try {
            const rpcList = Object.entries(this.cryptoApp.savedRpcs);
            
            if (rpcList.length === 0) {
                this.controllerBot.sendMessage(chatId, '📭 Tidak ada RPC tersimpan.');
                return;
            }

            let message = '📡 DAFTAR RPC:\n\n';
            const buttons = [];

            rpcList.forEach(([key, rpc], index) => {
                const isActive = this.cryptoApp.currentRpc === rpc.rpc;
                
                message += `${isActive ? '🟢 ' : '⚪️ '}${index + 1}. ${rpc.name}\n`;
                message += `   🔗 ${rpc.rpc}\n`;
                message += `   ⛓️ Chain: ${rpc.chainId}\n\n`;

                buttons.push([
                    { 
                        text: `${isActive ? '🟢 ' : ''}${rpc.name}`, 
                        callback_data: `rpc_use_${key}` 
                    }
                ]);
            });

            buttons.push([{ text: '🔙 Kembali', callback_data: 'rpc_menu' }]);

            this.controllerBot.sendMessage(chatId, message, {
                reply_markup: { inline_keyboard: buttons }
            });

        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Error: ${error.message}`);
        }
    }

    async selectRpc(chatId, rpcKey) {
        try {
            const selectedRpc = this.cryptoApp.savedRpcs[rpcKey];
            
            if (selectedRpc) {
                this.cryptoApp.currentRpc = selectedRpc.rpc;
                this.cryptoApp.currentChainId = selectedRpc.chainId;
                this.cryptoApp.currentRpcName = selectedRpc.name;
                this.cryptoApp.setupProvider();
                this.cryptoApp.saveRpcConfig();

                this.controllerBot.sendMessage(chatId,
                    `✅ RPC DIPILIH!\n\n` +
                    `🏷️ ${selectedRpc.name}\n` +
                    `🔗 ${selectedRpc.rpc}\n` +
                    `⛓️ Chain: ${selectedRpc.chainId}`
                );

                this.sendNotification(`🌐 RPC Changed: ${selectedRpc.name}`);
            }
        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Error: ${error.message}`);
        }
    }

    // ===================================
    // INFO & STATUS
    // ===================================
    
    showInfoMenu(chatId) {
         if (!this.isAuthenticated || chatId !== this.currentUser.chatId) return;

         const menu = {
             reply_markup: {
                 inline_keyboard: [
                     [
                         { text: '🤖 Status Bot', callback_data: 'info_status' },
                         { text: '💰 Cek Balance', callback_data: 'wallet_balance' }
                     ],
                     [
                         { text: '📊 TX Stats', callback_data: 'wallet_stats' },
                         { text: 'ℹ️ Info RPC', callback_data: 'rpc_info' }
                     ],
                     [
                         { text: '🔙 Main Menu', callback_data: 'main_menu' }
                     ]
                 ]
             }
         };
         this.controllerBot.sendMessage(chatId, '📊 INFO & STATUS:', menu);
    }


    async checkBalance(chatId) {
        if (!this.cryptoApp.wallet) {
            this.controllerBot.sendMessage(chatId, '❌ Belum ada wallet yang dipilih.');
            return;
        }

        try {
            this.controllerBot.sendMessage(chatId, '🔄 Mengecek balance...');
            
            const balanceInfo = await this.cryptoApp.checkBalance(); 
            
            if (balanceInfo) {
                // [FIX 3 - PARSING ERROR] Hapus parse_mode
                this.controllerBot.sendMessage(chatId,
                    `💰 BALANCE INFO\n\n` +
                    `🏷️ Wallet: ${this.cryptoApp.wallet.address}\n` + // [FIX 3 - PARSING ERROR] Hapus backticks
                    `💰 Balance: ${balanceInfo.balance} ETH\n` +
                    `📊 Total TX: ${balanceInfo.txCount}\n` +
                    `⛓️ Chain: ${this.cryptoApp.currentChainId}\n` +
                    `🌐 RPC: ${this.cryptoApp.currentRpcName}`
                );
            }
        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Error: ${error.message}`);
        }
    }

    async sendBotStatus(chatId) {
        const status = this.cryptoApp.isConnected ? '🟢 TERHUBUNG' : '🔴 TIDAK TERHUBUNG';
        const walletInfo = this.cryptoApp.wallet ? 
            `\n💳 Wallet: ${this.cryptoApp.wallet.address}` : // [FIX 3 - PARSING ERROR] Hapus backticks
            '\n💳 Wallet: Belum setup';

        const wallets = await this.cryptoApp.loadWallets();
        const totalWallets = Object.keys(wallets).length;

        // [FIX 3 - PARSING ERROR] Hapus parse_mode
        this.controllerBot.sendMessage(chatId,
            `🤖 BOT STATUS\n\n` +
            `Status: ${status}` +
            `${walletInfo}\n` +
            `💼 Total Wallets: ${totalWallets}\n` +
            `⛓️ Chain ID: ${this.cryptoApp.currentChainId}\n` +
            `🌐 RPC: ${this.cryptoApp.currentRpcName}\n` +
            `🔑 WC Project: ${this.config.WALLETCONNECT_PROJECT_ID?.slice(0, 8)}...\n\n` +
            `🕒 ${new Date().toLocaleString()}`
        );
    }

    // ===================================
    // MESSAGE & CALLBACK HANDLERS
    // ===================================

    async handleMessage(msg) {
        const chatId = msg.chat.id;
        const text = msg.text;

        if (!text) return;
        
        if (text.startsWith('/start')) {
             await this.startSecurityFlow(chatId);
             return;
        }

        if (!this.isAuthenticated) {
            await this.handleSecurityMessage(chatId, text, msg);
            return;
        }
        
        if (chatId !== this.currentUser.chatId) {
            this.controllerBot.sendMessage(chatId, '❌ Anda tidak diautorisasi.');
            return;
        }

        // Handle main menu commands
        if (text === '💼 Wallet Management') {
            this.showWalletMenu(chatId);
        } else if (text === '📊 Info & Status') {
            this.showInfoMenu(chatId);
        } else if (text === '🌐 RPC Management') {
            this.showRpcMenu(chatId);
        } else if (text === '🔗 WalletConnect') {
            this.showWalletConnectMenu(chatId);
        } else if (text === '🔐 Logout') {
            this.logout(chatId);
        } else {
            // Handle state-based inputs
            const userState = this.userStates.get(chatId);
            if (userState) {
                await this.handleUserState(chatId, text, userState, msg);
            }
        }
    }

    async handleSecurityMessage(chatId, text, msg) {
        const userState = this.userStates.get(chatId);

        if (!userState) {
            if (text === '1. Administrator Access') {
                this.userStates.set(chatId, { 
                    action: 'awaiting_admin_password',
                    loginType: 'admin',
                    attempts: 0
                });
                this.controllerBot.sendMessage(chatId,
                    `🔐 ADMINISTRATOR LOGIN\n\n` +
                    `» Enter administrator password:`
                );
            } else if (text === '2. Script Password Access') {
                this.userStates.set(chatId, { 
                    action: 'awaiting_script_password', 
                    loginType: 'script',
                    attempts: 0
                });
                this.controllerBot.sendMessage(chatId,
                    `🔐 SCRIPT LOGIN\n\n` +
                    `» Enter script password:`
                );
            }
        } else {
            await this.handlePasswordInput(chatId, text, userState, msg);
        }
    }

    async handleUserState(chatId, text, userState, msg) {
        // Hapus pesan inputan user agar bersih (kecuali password, sudah dihandle)
        if(userState.action !== 'awaiting_admin_password' && userState.action !== 'awaiting_script_password') {
            try { await this.controllerBot.deleteMessage(chatId, msg.message_id); } catch(e) {}
        }

        switch (userState.action) {
            case 'awaiting_notification_chat_id':
                await this.processNotificationChatId(chatId, text);
                break;
            case 'awaiting_wallet_import':
                await this.processWalletImport(chatId, text, msg);
                break;
            case 'awaiting_wallet_name':
                await this.processWalletName(chatId, text);
                break;
            case 'awaiting_wc_uri':
                await this.processWalletConnectURI(chatId, text, msg);
                break;
            case 'awaiting_rpc_add':
                await this.processAddRpc(chatId, text, userState);
                break;
        }
    }

    async handleCallback(query) {
        const chatId = query.message.chat.id;
        const data = query.data;

        if (!this.isAuthenticated || chatId !== this.currentUser.chatId) {
             this.controllerBot.answerCallbackQuery(query.id, { text: '❌ Otorisasi Gagal. /start ulang.' });
             return;
        }
        
        try {
            // Main menu
            if (data === 'main_menu') {
                this.showMainMenu(chatId);
            }
            // Wallet management
            else if (data === 'wallet_menu') {
                this.showWalletMenu(chatId);
            }
            // [DIHAPUS] else if (data === 'wallet_create')
            else if (data === 'wallet_import') {
                await this.importWalletFlow(chatId);
            }
            else if (data === 'wallet_list') {
                await this.listWallets(chatId, 'wallet_select_'); // Prefix default
            }
            else if (data === 'wallet_balance') {
                await this.checkBalance(chatId);
            }
             else if (data === 'wallet_stats') {
                await this.getTransactionStats(chatId);
            }
            else if (data.startsWith('wallet_select_')) {
                const address = data.replace('wallet_select_', '');
                await this.selectWallet(chatId, address);
                
                // [FIX 2 - TAMPILKAN MENU KEMBALI]
                this.showWalletMenu(chatId); 
                // [END FIX 2]
            }
            else if (data === 'wallet_delete_menu') {
                await this.showDeleteWalletMenu(chatId);
            }
            else if (data.startsWith('wallet_delete_confirm_')) {
                const address = data.replace('wallet_delete_confirm_', '');
                await this.confirmDeleteWallet(chatId, address);
            }
             else if (data.startsWith('wallet_delete_exec_')) {
                const address = data.replace('wallet_delete_exec_', '');
                await this.executeDeleteWallet(chatId, address);
            }
            
            // [BARU] WalletConnect flow
            else if (data === 'wc_menu') {
                 this.showWalletConnectMenu(chatId);
            }
            else if (data === 'wc_select_wallet') {
                 await this.listWallets(chatId, 'wc_wallet_picked_'); // Prefix WC
            }
             else if (data.startsWith('wc_wallet_picked_')) {
                const address = data.replace('wc_wallet_picked_', '');
                await this.selectWallet(chatId, address); // Pilih wallet
                this.showWalletConnectMenu(chatId); // Tampilkan menu WC lagi
            }
            else if (data === 'wc_connect') {
                await this.startWalletConnect(chatId);
            }
            else if (data === 'wc_status') {
                await this.sendBotStatus(chatId);
            }
            else if (data === 'wc_disconnect') {
                this.cryptoApp.cleanup(); 
                this.controllerBot.sendMessage(chatId, '✅ WalletConnect disconnected.');
                this.showWalletConnectMenu(chatId); 
            }
            
            // RPC management
            else if (data === 'rpc_menu') {
                this.showRpcMenu(chatId);
            }
            else if (data === 'rpc_select') {
                await this.showRpcList(chatId);
            }
            else if (data === 'rpc_add') {
                await this.startAddRpcFlow(chatId, 1, {});
            }
             else if (data === 'rpc_info') {
                await this.showRpcInfo(chatId);
            }
             else if (data === 'rpc_delete_menu') {
                 await this.showDeleteRpcMenu(chatId);
            }
             else if (data === 'rpc_delete_active') {
                 this.controllerBot.answerCallbackQuery(query.id, { text: '❌ Tidak bisa hapus RPC aktif', show_alert: true });
                 return; 
            }
             else if (data.startsWith('rpc_delete_exec_')) {
                const rpcKey = data.replace('rpc_delete_exec_', '');
                await this.executeDeleteRpc(chatId, rpcKey);
            }
            else if (data.startsWith('rpc_use_')) {
                const rpcKey = data.replace('rpc_use_', '');
                await this.selectRpc(chatId, rpcKey);
            }
            
            // Info Menu
             else if (data === 'info_menu') {
                 this.showInfoMenu(chatId);
            }
            else if (data === 'info_status') {
                 await this.sendBotStatus(chatId);
            }


            this.controllerBot.answerCallbackQuery(query.id);
        } catch (error) {
            this.controllerBot.sendMessage(chatId, `❌ Error: ${error.message}`);
            this.controllerBot.answerCallbackQuery(query.id);
        }
    }

    // ===================================
    // UTILITY METHODS
    // ===================================

    sendNotification(message) {
        if (this.notificationBot && this.config.TELEGRAM_CHAT_ID) {
            try {
                this.notificationBot.sendMessage(this.config.TELEGRAM_CHAT_ID, message);
            } catch (error) {
                console.log('❌ Error sending notification:', error.message);
            }
        }
    }

    logout(chatId) {
        this.isAuthenticated = false;
        this.currentUser = null;
        this.userStates.clear();
        
        if (this.cryptoApp) {
            this.cryptoApp.cleanup();
        }
        
        const menu = { reply_markup: { remove_keyboard: true } };

        this.controllerBot.sendMessage(chatId,
            `🔐 LOGGED OUT\n\n` +
            `Sesi telah berakhir.\n\n` +
            `Kirim /start untuk login kembali.`,
            menu
        );
    }

    cleanup() {
        if (this.controllerBot) {
            this.controllerBot.stopPolling();
            console.log('🎛️ Controller Bot stopped.');
        }
        if (this.cryptoApp) {
            this.cryptoApp.cleanup();
            console.log('🤖 Crypto App cleaned up.');
        }
    }
}

// ===================================
// == MODIFIKASI MAIN FUNCTION
// ===================================

/**
 * @function main
 * @description Titik masuk utama aplikasi.
 * Memprioritaskan mode Telegram Controller jika token ada,
 * jika tidak, kembali ke mode Terminal.
 */
async function main() {
    const ui = new ModernUI();
    let telegramController = null;

    try {
        await ui.showAnimatedBanner(1, 0);
        const SECURE_CONFIG = loadConfiguration();
        
        // PILIHAN MODE: TELEGRAM atau CLI
        // Ini dikontrol oleh .env file Anda.
        if (SECURE_CONFIG.TELEGRAM_CONTROLLER_TOKEN) {
            // == MODE TELEGRAM ==
            console.log('🎛️ Starting Telegram Full Controller...');
            
            telegramController = new TelegramFullController(SECURE_CONFIG);
            
            console.log('✅ Telegram Full Controller Active!');
            console.log('📱 All features available via Telegram');
            console.log(`🔐 Login via: /start di Bot Controller Anda`);
            
            process.on('SIGINT', () => {
                console.log('\n👋 Bot stopped by user (Ctrl+C). Cleaning up Telegram Controller...');
                if (telegramController) {
                    telegramController.cleanup();
                }
                process.exit(0);
            });
            
        } else {
            // == MODE TERMINAL (CLI) ==
            ui.showNotification('warning', 'TOKEN KONTROL TELEGRAM TIDAK DITEMUKAN', [
                'TELEGRAM_CONTROLLER_TOKEN tidak ada di file .env.',
                'Menjalankan mode terminal (CLI)...'
            ]);
            await ui.sleep(2000);
            
            await runTerminalMode(SECURE_CONFIG);
        }

    } catch (error) {
        ui.stopLoading();
        ui.showNotification('error', 'FATAL APPLICATION ERROR', [error.message, error.stack]);
        console.log(error);
        
        if (telegramController) {
            telegramController.cleanup();
        }
        
        process.exit(1);
    }
}

// Start the application
main();