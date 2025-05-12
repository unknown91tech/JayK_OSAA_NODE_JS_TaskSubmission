// config/db.js - Fixed with proper ENUM handling
const { Sequelize } = require('sequelize');
require('dotenv').config();

// Create base configuration
const dbConfig = {
  dialect: 'postgres',
  logging: process.env.NODE_ENV === 'development' ? console.log : false,
  // Connection pool configuration for better performance
  pool: {
    max: 10,
    min: 0,
    acquire: 30000,
    idle: 10000
  },
  // Retry configuration
  retry: {
    max: 3
  },
  // Define custom options to handle ENUM issues
  dialectOptions: {
    // Add any SSL configuration if needed
    ...(process.env.NODE_ENV === 'production' && {
      ssl: {
        require: true,
        rejectUnauthorized: false
      }
    }),
    keepAlive: true,
    statement_timeout: 1000
  },
  // Define hooks to handle ENUM alterations properly
  define: {
    // This helps with ENUM handling
    charset: 'utf8',
    collate: 'utf8_general_ci'
  }
};

// Create Sequelize instance
const sequelize = new Sequelize(process.env.DATABASE_URL, dbConfig);

// Function to safely create or alter ENUM types
const safeAlterColumn = async (tableName, columnName, enumValues) => {
  try {
    const queryInterface = sequelize.getQueryInterface();
    
    // Get current table structure
    const tableDescription = await queryInterface.describeTable(tableName);
    
    if (tableDescription[columnName]) {
      console.log(`📝 Checking ${tableName}.${columnName} for ENUM changes...`);
      
      // Instead of altering the column, we'll handle this differently
      // First, check if the enum type already exists
      const [results] = await sequelize.query(`
        SELECT EXISTS (
          SELECT 1 FROM pg_type 
          WHERE typname = 'enum_${tableName}_${columnName}'
        );
      `);
      
      const enumExists = results[0].exists;
      
      if (!enumExists) {
        // Create the enum type if it doesn't exist
        const enumName = `enum_${tableName}_${columnName}`;
        const enumQuery = `
          CREATE TYPE ${enumName} AS ENUM (${enumValues.map(v => `'${v}'`).join(', ')});
        `;
        
        await sequelize.query(enumQuery);
        console.log(`✅ Created ENUM type: ${enumName}`);
      }
    }
  } catch (error) {
    console.error(`⚠️ Warning: Could not check/create ENUM for ${tableName}.${columnName}:`, error.message);
    // Don't throw - let the normal sync process handle it
  }
};

const connectDB = async () => {
  try {
    console.log('🔗 Establishing database connection...');
    
    // Test the database connection
    await sequelize.authenticate();
    console.log('✅ Database connection established successfully');
    
    // Check if tables already exist
    const tables = await sequelize.getQueryInterface().showAllTables();
    const hasExistingTables = tables.length > 0;
    
    if (hasExistingTables) {
      console.log(`📋 Found ${tables.length} existing tables in database`);
      console.log('🔄 Syncing models with existing database...');
      
      // Handle specific ENUM issues before syncing
      try {
        // Pre-create ENUM types that might cause issues
        await safeAlterColumn('OtpLogs', 'otpType', ['REGISTRATION', 'LOGIN', 'PASSWORD_RESET', 'ACCOUNT_CHANGE']);
        await safeAlterColumn('OtpLogs', 'status', ['GENERATED', 'DELIVERED', 'VERIFIED', 'EXPIRED', 'FAILED']);
        await safeAlterColumn('OtpLogs', 'deliveryMethod', ['TELEGRAM', 'WHATSAPP']);
        await safeAlterColumn('ActivityLogs', 'category', ['AUTH', 'MFA', 'ROLE', 'ACCESS', 'SECURITY', 'SYSTEM']);
        await safeAlterColumn('ActivityLogs', 'severity', ['INFO', 'WARNING', 'ALERT', 'ERROR']);
        await safeAlterColumn('ActivityLogs', 'status', ['SUCCESS', 'FAILURE', 'BLOCKED', 'ATTEMPTED']);
      } catch (enumError) {
        console.warn('⚠️ Warning: ENUM pre-creation had issues:', enumError.message);
      }
      
      // Sync models with force: false and alter: false to avoid destructive changes
      const syncOptions = {
        force: false,
        alter: false // Disable alter to avoid ENUM issues
      };
      
      // If in development, we can be more flexible
      if (process.env.NODE_ENV === 'development') {
        console.log('🔧 Development mode: Will attempt safe alterations...');
        // Use a more conservative approach even in development
        syncOptions.alter = {
          drop: false // Don't drop anything
        };
      }
      
      await sequelize.sync(syncOptions);
      
      console.log('✅ Database models synchronized with existing data');
      
      // Check if essential tables exist and create only missing ones
      const requiredTables = ['Users', 'Roles', 'UserRoles', 'Tokens', 'ActivityLogs', 'LoginAttempts', 'OtpLogs'];
      const existingTableNames = tables.map(table => table.toLowerCase());
      const missingTables = requiredTables.filter(table => 
        !existingTableNames.includes(table.toLowerCase())
      );
      
      if (missingTables.length > 0) {
        console.log(`⚠️ Missing required tables: ${missingTables.join(', ')}`);
        console.log('🔧 Creating missing tables...');
        
        // For missing tables, we can be more aggressive
        await sequelize.sync({ force: false, alter: false });
        console.log('✅ Missing tables created');
      }
      
      return { isNewDatabase: false };
    } else {
      console.log('🆕 No existing tables found - initializing new database');
      
      // For new databases, we can sync normally
      await sequelize.sync({ force: false });
      console.log('✅ Database models synchronized for new installation');
      
      return { isNewDatabase: true };
    }
  } catch (error) {
    console.error('❌ Unable to connect to the database:', error);
    
    // More specific error handling
    if (error.original) {
      if (error.original.code === 'ECONNREFUSED') {
        console.error('💡 Tip: Make sure PostgreSQL is running');
      } else if (error.original.code === '3D000') {
        console.error('💡 Tip: Database does not exist. Create it with: createdb auth_db');
      } else if (error.original.code === '42601' && error.message.includes('USING')) {
        console.error('💡 Tip: ENUM syntax error - trying alternative approach...');
        
        // Try a more conservative sync
        try {
          console.log('🔄 Attempting conservative database sync...');
          await sequelize.sync({ force: false, alter: false });
          console.log('✅ Conservative sync successful');
          return { isNewDatabase: false };
        } catch (retryError) {
          console.error('❌ Conservative sync also failed:', retryError.message);
        }
      }
    }
    
    if (process.env.NODE_ENV !== 'production') {
      // In development, offer to recreate the database
      console.log('\n💡 Development Tip: If the database structure is incompatible,');
      console.log('you might want to recreate it:');
      console.log('   dropdb auth_db && createdb auth_db');
      console.log('   npm start');
    }
    
    process.exit(1);
  }
};

// Graceful shutdown function
const closeConnection = async () => {
  try {
    console.log('🔄 Closing database connection...');
    await sequelize.close();
    console.log('✅ Database connection closed');
  } catch (error) {
    console.error('❌ Error closing database connection:', error);
  }
};

module.exports = { sequelize, connectDB, closeConnection };