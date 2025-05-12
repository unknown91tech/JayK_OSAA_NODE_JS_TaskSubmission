const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');
const { v4: uuidv4 } = require('uuid');

const OtpLog = sequelize.define('OtpLog', {
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
  otpType: {
    type: DataTypes.ENUM('REGISTRATION', 'LOGIN', 'PASSWORD_RESET', 'ACCOUNT_CHANGE'),
    allowNull: false,
    comment: 'Purpose of this OTP'
  },
  ipAddress: {
    type: DataTypes.STRING,
    allowNull: false
  },
  userAgent: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  status: {
    type: DataTypes.ENUM('GENERATED', 'DELIVERED', 'VERIFIED', 'EXPIRED', 'FAILED'),
    allowNull: false,
    defaultValue: 'GENERATED'
  },
  deliveryMethod: {
    type: DataTypes.ENUM('TELEGRAM', 'WHATSAPP'),
    allowNull: false
  },
  validUntil: {
    type: DataTypes.DATE,
    allowNull: false
  },
  verifiedAt: {
    type: DataTypes.DATE,
    allowNull: true
  },
  failureReason: {
    type: DataTypes.STRING,
    allowNull: true
  }
}, {
  timestamps: true,
  hooks: {
    beforeCreate: async (otpLog) => {
      // Generate a UUID if not provided
      if (!otpLog.id) {
        otpLog.id = uuidv4();
      }
    }
  }
});

module.exports = OtpLog;