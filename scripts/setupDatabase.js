// scripts/setupDatabase.js
const { sequelize } = require('../config/db');
const { initializeModels } = require('../models');
require('dotenv').config();

const setupDatabase = async () => {
  try {
    console.log('🏗️ Setting up database...');
    
    // Initialize models
    initializeModels();
    
    // Authenticate connection
    await sequelize.authenticate();
    console.log('✅ Database connection established');
    
    // Sync all models
    console.log('🔄 Syncing database models...');
    await sequelize.sync({ force: false });
    console.log('✅ Database models synchronized');
    
    // Run any additional setup
    console.log('📋 Database setup complete');
    console.log('💡 Run "npm run create-roles" to create default roles');
    
    process.exit(0);
  } catch (error) {
    console.error('❌ Database setup failed:', error);
    process.exit(1);
  }
};

setupDatabase();
