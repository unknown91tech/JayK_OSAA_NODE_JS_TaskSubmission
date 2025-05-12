const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');
const { v4: uuidv4 } = require('uuid');

const LoginAttempt = sequelize.define('LoginAttempt', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  userId: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'Users',
      key: 'id'
    }
  },
  ipAddress: {
    type: DataTypes.STRING,
    allowNull: false
  },
  successful: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  loginMethod: {
    type: DataTypes.STRING, // 'direct', 'telegram', 'whatsapp'
    allowNull: false
  },
  userAgent: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  mfaCompleted: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
    comment: 'Whether MFA verification was completed for this login attempt'
  },
  mfaType: {
    type: DataTypes.STRING,
    allowNull: true,
    comment: 'The type of MFA used (telegram, whatsapp, etc.)'
  }
}, {
  timestamps: true,
  hooks: {
    beforeCreate: async (loginAttempt) => {
      // Generate a UUID if not provided
      if (!loginAttempt.id) {
        loginAttempt.id = uuidv4();
      }
    }
  }
});

module.exports = LoginAttempt;