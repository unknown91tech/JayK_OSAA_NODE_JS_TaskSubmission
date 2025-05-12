// scripts/createDefaultRoles.js
const { Role } = require('../models');
const { connectDB } = require('../config/db');
require('dotenv').config();

const createDefaultRoles = async () => {
  try {
    await connectDB();
    console.log('📡 Connected to database');
    
    // Create admin role
    const [adminRole, adminCreated] = await Role.findOrCreate({
      where: { name: 'admin' },
      defaults: {
        description: 'Administrator with full system access',
        permissions: ['*']
      }
    });
    
    if (adminCreated) {
      console.log('✅ Created admin role');
    } else {
      console.log('📄 Admin role already exists');
    }
    
    // Create user role
    const [userRole, userCreated] = await Role.findOrCreate({
      where: { name: 'user' },
      defaults: {
        description: 'Standard user with basic access',
        permissions: ['profile:read', 'profile:update']
      }
    });
    
    if (userCreated) {
      console.log('✅ Created user role');
    } else {
      console.log('📄 User role already exists');
    }
    
    // Create moderator role
    const [modRole, modCreated] = await Role.findOrCreate({
      where: { name: 'moderator' },
      defaults: {
        description: 'Moderator with limited admin access',
        permissions: ['user:read', 'role:read', 'logs:read']
      }
    });
    
    if (modCreated) {
      console.log('✅ Created moderator role');
    } else {
      console.log('📄 Moderator role already exists');
    }
    
    console.log('✅ Default roles setup complete');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error creating default roles:', error);
    process.exit(1);
  }
};

createDefaultRoles();