// scripts/createAdminUser.js
const { User, Role, UserRole } = require('../models');
const { connectDB } = require('../config/db');
const bcrypt = require('bcrypt');
require('dotenv').config();

const createAdminUser = async () => {
  try {
    await connectDB();
    console.log('👤 Creating admin user...');
    
    // Get admin credentials from environment or prompt
    const username = process.env.ADMIN_USERNAME || 'admin';
    const passcode = process.env.ADMIN_PASSWORD || 'AdminPassword123!';
    const telegramId = process.env.ADMIN_TELEGRAM_ID;
    
    if (!telegramId) {
      console.error('❌ ADMIN_TELEGRAM_ID environment variable is required');
      process.exit(1);
    }
    
    // Check if admin already exists
    const existingAdmin = await User.findOne({ where: { username } });
    if (existingAdmin) {
      console.log('📄 Admin user already exists');
      process.exit(0);
    }
    
    // Create admin user
    const adminUser = await User.create({
      username,
      passcode,
      dateOfBirth: '1990-01-01',
      registrationMethod: 'telegram',
      telegramId,
      isVerified: true,
      mfaEnabled: true
    });
    
    // Get admin role
    const adminRole = await Role.findOne({ where: { name: 'admin' } });
    if (!adminRole) {
      console.error('❌ Admin role not found. Run "npm run create-roles" first');
      process.exit(1);
    }
    
    // Assign admin role
    await UserRole.create({
      userId: adminUser.id,
      roleId: adminRole.id,
      assignedBy: adminUser.id,
      assignedAt: new Date()
    });
    
    console.log('✅ Admin user created successfully');
    console.log(`📌 Username: ${username}`);
    console.log(`📌 Telegram ID: ${telegramId}`);
    console.log('🔑 Make sure to change the password after first login');
    
    process.exit(0);
  } catch (error) {
    console.error('❌ Error creating admin user:', error);
    process.exit(1);
  }
};

createAdminUser();