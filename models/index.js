// models/index.js - Updated to include Challenge model
const { User, initializeAssociations } = require('./User');
const Role = require('./Role');
const UserRole = require('./UserRole');
const Token = require('./Token');
const LoginAttempt = require('./LoginAttempt');
const OtpLog = require('./OtpLog');
const ActivityLog = require('./ActivityLog');
const Challenge = require('./Challenge'); // Add Challenge model
const { sequelize } = require('../config/db');

// Initialize all model associations
const initializeModels = async () => {
  try {
    console.log('🔧 Initializing model associations...');
    
    // Initialize User-Role associations
    initializeAssociations();
    
    // Set up other associations
    User.hasMany(Token, { foreignKey: 'userId', onDelete: 'CASCADE' });
    Token.belongsTo(User, { foreignKey: 'userId' });
    
    User.hasMany(LoginAttempt, { foreignKey: 'userId', onDelete: 'CASCADE' });
    LoginAttempt.belongsTo(User, { foreignKey: 'userId' });
    
    User.hasMany(OtpLog, { foreignKey: 'userId', onDelete: 'CASCADE' });
    OtpLog.belongsTo(User, { foreignKey: 'userId' });
    
    User.hasMany(ActivityLog, { foreignKey: 'userId', onDelete: 'SET NULL' });
    ActivityLog.belongsTo(User, { foreignKey: 'userId' });
    
    // Add Challenge associations
    User.hasMany(Challenge, { foreignKey: 'userId', onDelete: 'CASCADE' });
    Challenge.belongsTo(User, { foreignKey: 'userId' });
    
    console.log('✅ Model associations initialized successfully');
    
    // Check for existing default roles
    await ensureDefaultRoles();
    
    return true;
  } catch (error) {
    console.error('❌ Error initializing models:', error);
    return false;
  }
};

// Ensure default roles exist (keeping existing function)
const ensureDefaultRoles = async () => {
  try {
    console.log('🔍 Checking for default roles...');
    
    const roleCount = await Role.count();
    
    if (roleCount === 0) {
      console.log('📝 Creating default roles...');
      
      await Role.findOrCreate({
        where: { name: 'admin' },
        defaults: {
          description: 'Administrator with full system access',
          permissions: ['*']
        }
      });
      
      await Role.findOrCreate({
        where: { name: 'user' },
        defaults: {
          description: 'Standard user with basic access',
          permissions: ['profile:read', 'profile:update']
        }
      });
      
      await Role.findOrCreate({
        where: { name: 'moderator' },
        defaults: {
          description: 'Moderator with limited admin access',
          permissions: ['user:read', 'role:read', 'logs:read']
        }
      });
      
      console.log('✅ Default roles created');
    } else {
      console.log(`📋 Found ${roleCount} existing roles - skipping creation`);
      
      const adminRole = await Role.findOne({ where: { name: 'admin' } });
      const userRole = await Role.findOne({ where: { name: 'user' } });
      
      if (!adminRole) {
        console.log('⚠️  Admin role missing - creating...');
        await Role.create({
          name: 'admin',
          description: 'Administrator with full system access',
          permissions: ['*']
        });
      }
      
      if (!userRole) {
        console.log('⚠️  User role missing - creating...');
        await Role.create({
          name: 'user',
          description: 'Standard user with basic access',
          permissions: ['profile:read', 'profile:update']
        });
      }
      
      console.log('✅ Role verification complete');
    }
  } catch (error) {
    console.error('❌ Error ensuring default roles:', error);
  }
};

// Function to check database health (updated)
const checkDatabaseHealth = async () => {
  try {
    console.log('🏥 Performing database health check...');
    
    const tables = await sequelize.getQueryInterface().showAllTables();
    const requiredTables = ['Users', 'Roles', 'UserRoles', 'Tokens', 'ActivityLogs', 'LoginAttempts', 'OtpLogs', 'Challenges'];
    
    const missingTables = requiredTables.filter(table => 
      !tables.some(existingTable => existingTable.toLowerCase() === table.toLowerCase())
    );
    
    if (missingTables.length > 0) {
      console.warn(`⚠️  Missing tables: ${missingTables.join(', ')}`);
      console.log('🔧 Attempting to create missing tables...');
      await sequelize.sync({ force: false });
      console.log('✅ Missing tables created');
    }
    
    // Check for orphaned tokens
    const orphanedTokens = await Token.count({
      include: [{
        model: User,
        required: false,
        where: { id: null }
      }]
    });
    
    if (orphanedTokens > 0) {
      console.log(`🧹 Found ${orphanedTokens} orphaned tokens - cleaning up...`);
      await Token.destroy({
        where: {
          userId: {
            [sequelize.Op.notIn]: sequelize.literal('(SELECT id FROM "Users")')
          }
        }
      });
      console.log('✅ Orphaned tokens cleaned up');
    }
    
    // Check for orphaned challenges
    const orphanedChallenges = await Challenge.count({
      include: [{
        model: User,
        required: false,
        where: { id: null }
      }]
    });
    
    if (orphanedChallenges > 0) {
      console.log(`🧹 Found ${orphanedChallenges} orphaned challenges - cleaning up...`);
      await Challenge.destroy({
        where: {
          userId: {
            [sequelize.Op.notIn]: sequelize.literal('(SELECT id FROM "Users")')
          }
        }
      });
      console.log('✅ Orphaned challenges cleaned up');
    }
    
    console.log('✅ Database health check completed');
    return true;
  } catch (error) {
    console.error('❌ Database health check failed:', error);
    return false;
  }
};

// Function to migrate existing data if needed (updated)
const migrateExistingData = async () => {
  try {
    console.log('🔄 Checking for data migration needs...');
    
    const tableDescription = await sequelize.getQueryInterface().describeTable('Users');
    
    if (!tableDescription.mfaEnabled) {
      console.log('📝 Adding mfaEnabled field to existing Users...');
      await sequelize.getQueryInterface().addColumn('Users', 'mfaEnabled', {
        type: sequelize.DataTypes.BOOLEAN,
        defaultValue: true,
        allowNull: false
      });
      console.log('✅ mfaEnabled field added');
    }
    
    console.log('✅ Data migration check completed');
    return true;
  } catch (error) {
    console.error('❌ Data migration failed:', error);
    return false;
  }
};

module.exports = {
  User,
  Role,
  UserRole,
  Token,
  LoginAttempt,
  OtpLog,
  ActivityLog,
  Challenge, // Export Challenge model
  initializeModels,
  checkDatabaseHealth,
  migrateExistingData
};