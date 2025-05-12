const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');
const { v4: uuidv4 } = require('uuid');

const ActivityLog = sequelize.define('ActivityLog', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  userId: {
    type: DataTypes.UUID,
    allowNull: true, // Nullable for activities not tied to a user
    references: {
      model: 'Users',
      key: 'id'
    }
  },
  action: {
    type: DataTypes.STRING,
    allowNull: false,
    comment: 'The type of activity being logged'
  },
  category: {
    type: DataTypes.ENUM(
      'AUTH', // Login, logout, registration
      'MFA', // OTP generation, verification
      'ROLE', // Role changes
      'ACCESS', // Endpoint access
      'SECURITY', // Security-related events
      'SYSTEM' // System events
    ),
    allowNull: false
  },
  severity: {
    type: DataTypes.ENUM(
      'INFO', // Normal activity
      'WARNING', // Suspicious activity
      'ALERT', // Potentially malicious activity
      'ERROR' // System errors
    ),
    defaultValue: 'INFO'
  },
  details: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Additional details about the activity'
  },
  ipAddress: {
    type: DataTypes.STRING,
    allowNull: false
  },
  userAgent: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  resourceId: {
    type: DataTypes.STRING,
    allowNull: true,
    comment: 'ID of the resource being accessed (endpoint, data, etc.)'
  },
  status: {
    type: DataTypes.ENUM('SUCCESS', 'FAILURE', 'BLOCKED', 'ATTEMPTED'),
    allowNull: false
  },
  hashValue: {
    type: DataTypes.STRING,
    allowNull: true,
    comment: 'Hash of the log entry for integrity verification'
  }
}, {
  timestamps: true,
  hooks: {
    beforeCreate: async (log) => {
      // Generate a UUID if not provided
      if (!log.id) {
        log.id = uuidv4();
      }
    }
  },
  indexes: [
    { fields: ['userId'] },
    { fields: ['action'] },
    { fields: ['category'] },
    { fields: ['severity'] },
    { fields: ['status'] },
    { fields: ['createdAt'] }
  ]
});

module.exports = ActivityLog;