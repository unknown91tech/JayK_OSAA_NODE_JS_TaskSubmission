const TelegramBot = require('node-telegram-bot-api');
require('dotenv').config();

console.log('Initializing Telegram bot with token...');

// Create a bot that uses polling to get updates
const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: true });

// Add polling error handler
bot.on('polling_error', (error) => {
  console.error('Telegram bot polling error:', error);
});

// Test if the bot can connect
const testBotConnection = async () => {
  try {
    const botInfo = await bot.getMe();
    console.log('✅ Bot connected successfully:', botInfo);
    return true;
  } catch (error) {
    console.error('❌ Bot connection failed:', error);
    return false;
  }
};

// Generate a random 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send OTP to user via Telegram with improved error handling
const sendOTP = async (telegramId, otp) => {
  try {
    console.log(`📤 Attempting to send OTP ${otp} to Telegram ID: ${telegramId}`);
    
    const result = await bot.sendMessage(
      telegramId,
      `Your OTP for registration is: ${otp}\nThis code will expire in 10 minutes.`
    );
    
    console.log('✅ OTP sent successfully:', result.message_id);
    return true;
  } catch (error) {
    console.error(`❌ Error sending OTP via Telegram to ${telegramId}:`, error);
    return false;
  }
};

// Manual test function to send a message
const sendTestMessage = async (telegramId, message) => {
  try {
    console.log(`📤 Sending test message to Telegram ID: ${telegramId}`);
    const result = await bot.sendMessage(telegramId, message);
    console.log('✅ Test message sent:', result.message_id);
    return true;
  } catch (error) {
    console.error(`❌ Error sending test message:`, error);
    return false;
  }
};

// Initialize the bot and set up basic commands
const initTelegramBot = async () => {
  console.log('🤖 Initializing Telegram bot...');
  
  // Test connection first
  const connected = await testBotConnection();
  if (!connected) {
    console.error('❌ Failed to initialize Telegram bot - could not connect');
    return false;
  }
  
  // Handle /start command
  bot.onText(/\/start/, (msg) => {
    const chatId = msg.chat.id;
    console.log(`👋 User ${msg.from.username || msg.from.first_name} (ID: ${msg.from.id}) started conversation`);
    
    bot.sendMessage(
      chatId, 
      `Welcome to the Authentication System Bot! Your Telegram ID is: ${msg.from.id}\n\nUse this bot to receive OTPs for registration and login.`
    );
  });

  // Handle /help command
  bot.onText(/\/help/, (msg) => {
    const chatId = msg.chat.id;
    bot.sendMessage(
      chatId,
      'This bot helps you with authentication:\n' +
      '- You will receive OTPs for registration\n' +
      '- You can verify your account\n' +
      '- For any issues, please contact support'
    );
  });

  // Handle /id command to help users find their Telegram ID
  bot.onText(/\/id/, (msg) => {
    const chatId = msg.chat.id;
    bot.sendMessage(
      chatId,
      `Your Telegram ID is: ${msg.from.id}`
    );
  });
  
  // Log all incoming messages for debugging (remove in production)
  bot.on('message', (msg) => {
    console.log(`📩 Received message from ${msg.from.username || msg.from.first_name} (ID: ${msg.from.id}): ${msg.text}`);
  });

  console.log('✅ Telegram bot initialized successfully');
  return true;
};

/**
 * Send alert message to admin users
 * @param {string} message - Alert message to send
 * @returns {Promise<boolean>} - Success status
 */
const sendAdminAlert = async (message) => {
  try {
    if (!bot) {
      console.error('❌ Telegram bot not initialized');
      return false;
    }
    
    // Get admin Telegram IDs from database or config
    // This example uses environment variables for simplicity
    const adminTelegramIds = process.env.ADMIN_TELEGRAM_IDS 
      ? process.env.ADMIN_TELEGRAM_IDS.split(',') 
      : [];
    
    if (adminTelegramIds.length === 0) {
      console.warn('⚠️ No admin Telegram IDs configured');
      return false;
    }
    
    // Send alert to each admin
    const sendPromises = adminTelegramIds.map(telegramId => {
      return bot.sendMessage(telegramId, message, {
        parse_mode: 'Markdown'
      }).catch(err => {
        console.error(`❌ Failed to send alert to admin ${telegramId}:`, err);
        return null;
      });
    });
    
    // Wait for all messages to be sent
    const results = await Promise.all(sendPromises);
    
    // Check if at least one message was sent successfully
    const successCount = results.filter(result => result !== null).length;
    
    return successCount > 0;
  } catch (error) {
    console.error('❌ Failed to send admin alert:', error);
    return false;
  }
};

module.exports = {
  initTelegramBot,
  generateOTP,
  sendOTP,
  sendTestMessage,
  sendAdminAlert,
  bot
};