// scripts/checkDatabaseStatus.js - Check current database status
const { sequelize } = require('../config/db');
const { connectDB } = require('../config/db');
const { Role, User, Token, ActivityLog } = require('../models');
require('dotenv').config();

const checkDatabaseStatus = async () => {
  try {
    console.log('🔍 Checking database status...\n');
    
    // Connect to database
    const dbInfo = await connectDB();
    
    console.log('=== DATABASE STATUS REPORT ===\n');
    
    // 1. Check tables
    console.log('📋 TABLES:');
    const tables = await sequelize.getQueryInterface().showAllTables();
    console.log(`   Found ${tables.length} tables:`);
    tables.forEach((table, index) => {
      console.log(`   ${index + 1}. ${table}`);
    });
    console.log('');
    
    // 2. Check data counts
    console.log('📊 DATA COUNTS:');
    
    try {
      const userCount = await User.count();
      console.log(`   Users: ${userCount}`);
    } catch (e) {
      console.log('   Users: Table not accessible');
    }
    
    try {
      const roleCount = await Role.count();
      console.log(`   Roles: ${roleCount}`);
    } catch (e) {
      console.log('   Roles: Table not accessible');
    }
    
    try {
      const tokenCount = await Token.count();
      console.log(`   Active Tokens: ${tokenCount}`);
    } catch (e) {
      console.log('   Tokens: Table not accessible');
    }
    
    try {
      const logCount = await ActivityLog.count();
      console.log(`   Activity Logs: ${logCount}`);
    } catch (e) {
      console.log('   Activity Logs: Table not accessible');
    }
    console.log('');
    
    // 3. Check for essential roles
    console.log('👑 ESSENTIAL ROLES:');
    try {
      const adminRole = await Role.findOne({ where: { name: 'admin' } });
      const userRole = await Role.findOne({ where: { name: 'user' } });
      
      console.log(`   Admin role: ${adminRole ? '✅ Present' : '❌ Missing'}`);
      console.log(`   User role: ${userRole ? '✅ Present' : '❌ Missing'}`);
    } catch (e) {
      console.log('   Cannot check roles - table may not exist');
    }
    console.log('');
    
    // 4. Check for admin users
    console.log('👤 ADMIN USERS:');
    try {
      const adminRole = await Role.findOne({ where: { name: 'admin' } });
      if (adminRole) {
        const adminUsers = await adminRole.getUsers();
        console.log(`   Found ${adminUsers.length} admin user(s)`);
        adminUsers.forEach((user, index) => {
          console.log(`   ${index + 1}. ${user.username} (${user.isVerified ? 'Verified' : 'Not Verified'})`);
        });
      } else {
        console.log('   Admin role not found');
      }
    } catch (e) {
      console.log('   Cannot check admin users');
    }
    console.log('');
    
    // 5. Check database connection health
    console.log('🔗 CONNECTION HEALTH:');
    const connectionInfo = sequelize.config;
    console.log(`   Host: ${connectionInfo.host || 'localhost'}`);
    console.log(`   Database: ${connectionInfo.database}`);
    console.log(`   Username: ${connectionInfo.username}`);
    console.log(`   Dialect: ${connectionInfo.dialect}`);
    console.log(`   Pool Max: ${connectionInfo.pool?.max || 'Not configured'}`);
    console.log('');
    
    // 6. Recommendations
    console.log('💡 RECOMMENDATIONS:');
    
    if (dbInfo.isNewDatabase) {
      console.log('   ⚠️  This appears to be a new database');
      console.log('   📝 Run: npm run create-roles (to create default roles)');
      console.log('   👤 Run: npm run create-admin (to create admin user)');
    } else {
      console.log('   ✅ Existing database detected - data preserved');
    }
    
    const requiredTables = ['Users', 'Roles', 'UserRoles', 'Tokens', 'ActivityLogs'];
    const missingTables = requiredTables.filter(table => 
      !tables.some(existingTable => existingTable.toLowerCase() === table.toLowerCase())
    );
    
    if (missingTables.length > 0) {
      console.log(`   ❌ Missing tables: ${missingTables.join(', ')}`);
      console.log('   🔧 Run the application to auto-create missing tables');
    } else {
      console.log('   ✅ All required tables are present');
    }
    
    try {
      const adminRole = await Role.findOne({ where: { name: 'admin' } });
      const userRole = await Role.findOne({ where: { name: 'user' } });
      
      if (!adminRole || !userRole) {
        console.log('   ❌ Essential roles missing');
        console.log('   🔧 Run: npm run create-roles');
      }
    } catch (e) {
      console.log('   ⚠️  Cannot verify essential roles');
    }
    
    console.log('\n=== END OF REPORT ===');
    process.exit(0);
    
  } catch (error) {
    console.error('❌ Error checking database status:', error);
    
    if (error.name === 'SequelizeConnectionRefusedError') {
      console.error('\n💡 TROUBLESHOOTING:');
      console.error('   • Make sure PostgreSQL is running');
      console.error('   • Check your DATABASE_URL in .env file');
      console.error('   • Verify database credentials');
    } else if (error.name === 'SequelizeConnectionError') {
      console.error('\n💡 TROUBLESHOOTING:');
      console.error('   • Database might not exist - run: createdb auth_db');
      console.error('   • Check your DATABASE_URL format');
      console.error('   • Verify network connectivity');
    }
    
    process.exit(1);
  }
};

// Run if executed directly
if (require.main === module) {
  checkDatabaseStatus();
}

module.exports = { checkDatabaseStatus };