const { cleanupExpiredTokens } = require('../services/tokenService');
require('dotenv').config();

// Schedule token cleanup to run daily
const scheduleTokenCleanup = () => {
  console.log('📅 Scheduling token cleanup task');
  
  // Initial cleanup
  cleanupTokens();
  
  // Schedule to run once a day (24 hours)
  setInterval(cleanupTokens, 24 * 60 * 60 * 1000);
};

// Token cleanup function
const cleanupTokens = async () => {
  try {
    console.log('🧹 Running scheduled token cleanup task');
    const count = await cleanupExpiredTokens();
    console.log(`✅ Scheduled cleanup completed: ${count} expired tokens removed`);
  } catch (error) {
    console.error('❌ Scheduled token cleanup error:', error);
  }
};

module.exports = { scheduleTokenCleanup };