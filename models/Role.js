const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');
const { v4: uuidv4 } = require('uuid');

const Role = sequelize.define('Role', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  permissions: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'JSON array of permission strings'
  }
}, {
  timestamps: true,
  hooks: {
    beforeCreate: async (role) => {
      // Generate a UUID if not provided
      if (!role.id) {
        role.id = uuidv4();
      }
    }
  }
});

module.exports = Role;