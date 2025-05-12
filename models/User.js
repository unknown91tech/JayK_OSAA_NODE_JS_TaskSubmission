const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const Role = require('./Role');
const UserRole = require('./UserRole');

const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  username: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false
  },
  dateOfBirth: {
    type: DataTypes.DATEONLY,
    allowNull: false
  },
  passcode: {
    type: DataTypes.STRING,
    allowNull: false
  },
  referralCode: {
    type: DataTypes.STRING,
    allowNull: true
  },
  telegramId: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: true
  },
  whatsappNumber: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: true
  },
  registrationMethod: {
    type: DataTypes.ENUM('telegram', 'whatsapp'),
    allowNull: false
  },
  otpSecret: {
    type: DataTypes.STRING,
    allowNull: true
  },
  otpExpiresAt: {
    type: DataTypes.DATE,
    allowNull: true
  },
  isVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  mfaEnabled: {
    type: DataTypes.BOOLEAN,
    defaultValue: true,
    comment: 'Whether multi-factor authentication is enabled for this user'
  },
  lastLogin: {
    type: DataTypes.DATE,
    allowNull: true
  },
  failedLoginAttempts: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  },
  accountLocked: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  accountLockedUntil: {
    type: DataTypes.DATE,
    allowNull: true
  }
}, {
  timestamps: true,
  hooks: {
    beforeCreate: async (user) => {
      // Hash the passcode before storing in DB
      if (user.passcode) {
        user.passcode = await bcrypt.hash(user.passcode, 12);
      }
      
      // Generate a UUID if not provided
      if (!user.id) {
        user.id = uuidv4();
      }
    },
    beforeUpdate: async (user) => {
      // Hash the passcode on update if changed
      if (user.changed('passcode')) {
        user.passcode = await bcrypt.hash(user.passcode, 12);
      }
    }
  }
});

// Set up associations - this will be initialized after model definitions
const initializeAssociations = () => {
  // User to Role: Many-to-Many relationship
  User.belongsToMany(Role, { 
    through: UserRole,
    foreignKey: 'userId',
    otherKey: 'roleId'
  });

  Role.belongsToMany(User, {
    through: UserRole,
    foreignKey: 'roleId',
    otherKey: 'userId'
  });
};

// Instance method to compare passcode
User.prototype.comparePasscode = async function(candidatePasscode) {
  return await bcrypt.compare(candidatePasscode, this.passcode);
};

// Instance method to check if user has a specific role
User.prototype.hasRole = async function(roleName) {
  const roles = await this.getRoles();
  return roles.some(role => role.name === roleName);
};

// Instance method to check if user has any of the specified roles
User.prototype.hasAnyRole = async function(roleNames) {
  const roles = await this.getRoles();
  return roles.some(role => roleNames.includes(role.name));
};

// Instance method to get user permissions (combining all role permissions)
User.prototype.getPermissions = async function() {
  const roles = await this.getRoles({ include: ['permissions'] });
  const allPermissions = new Set();

  roles.forEach(role => {
    if (role.permissions && Array.isArray(role.permissions)) {
      role.permissions.forEach(permission => allPermissions.add(permission));
    }
  });

  return Array.from(allPermissions);
};

module.exports = { User, initializeAssociations };