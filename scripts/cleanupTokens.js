
// scripts/cleanupTokens.js
const { cleanupExpiredTokens } = require('../services/tokenService');
const { connectDB } = require('../config/db');
require('dotenv').config();

const cleanupTokens = async () => {
  try {
    await connectDB();
    console.log('🧹 Starting token cleanup...');
    
    const count = await cleanupExpiredTokens();
    console.log(`✅ Cleanup complete: ${count} expired tokens removed`);
    
    process.exit(0);
  } catch (error) {
    console.error('❌ Token cleanup failed:', error);
    process.exit(1);
  }
};

cleanupTokens();