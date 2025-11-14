require('dotenv').config();

const config = {
    telegram: {
        botToken: process.env.TELEGRAM_BOT_TOKEN,
        chatId: process.env.TELEGRAM_CHAT_ID
    },
    rpc: {
        testnet: process.env.RPC_URL_TESNET,
        chainId: parseInt(process.env.CHAIN_ID_TESNET)
    },
    walletConnect: {
        projectId: process.env.WALLETCONNECT_PROJECT_ID
    },
    app: {
        name: process.env.APP_NAME,
        description: process.env.APP_DESCRIPTION
    }
};

// Validasi config
if (!config.telegram.botToken) {
    console.error('❌ TELEGRAM_BOT_TOKEN tidak ditemukan di .env');
    process.exit(1);
}

if (!config.rpc.testnet) {
    console.error('❌ RPC_URL_TESNET tidak ditemukan di .env');
    process.exit(1);
}

if (!config.walletConnect.projectId) {
    console.error('❌ WALLETCONNECT_PROJECT_ID tidak ditemukan di .env');
    process.exit(1);
}

module.exports = config;