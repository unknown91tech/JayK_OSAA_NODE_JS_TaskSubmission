const { Role, User, UserRole } = require('../models');
const { Op } = require('sequelize');

/**
 * Get all roles (admin only)
 */
const getAllRoles = async (req, res) => {
  try {
    console.log('📋 Fetching all roles');
    
    const roles = await Role.findAll({
      order: [['name', 'ASC']]
    });
    
    res.status(200).json({
      success: true,
      roles
    });
  } catch (error) {
    console.error('❌ Error fetching roles:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while fetching roles'
    });
  }
};

/**
 * Get a single role by ID (admin only)
 */
const getRoleById = async (req, res) => {
  try {
    console.log(`🔍 Fetching role with ID: ${req.params.id}`);
    
    const role = await Role.findByPk(req.params.id);
    
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Role not found'
      });
    }
    
    res.status(200).json({
      success: true,
      role
    });
  } catch (error) {
    console.error('❌ Error fetching role:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while fetching the role'
    });
  }
};

/**
 * Create a new role (admin only)
 */
const createRole = async (req, res) => {
  try {
    console.log('✨ Creating new role');
    const { name, description, permissions } = req.body;
    
    // Check if role with the same name already exists
    const existingRole = await Role.findOne({ where: { name } });
    if (existingRole) {
      return res.status(400).json({
        success: false,
        message: 'Role with this name already exists'
      });
    }
    
    // Create the role
    const newRole = await Role.create({
      name,
      description,
      permissions
    });
    
    console.log(`✅ Created new role: ${name} with ID: ${newRole.id}`);
    
    res.status(201).json({
      success: true,
      message: 'Role created successfully',
      role: newRole
    });
  } catch (error) {
    console.error('❌ Error creating role:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while creating the role'
    });
  }
};

/**
 * Update an existing role (admin only)
 */
const updateRole = async (req, res) => {
  try {
    console.log(`🔄 Updating role with ID: ${req.params.id}`);
    const { name, description, permissions } = req.body;
    
    // Find the role
    const role = await Role.findByPk(req.params.id);
    
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Role not found'
      });
    }
    
    // Check if the role being updated is the protected system roles
    if (role.name === 'admin' || role.name === 'user') {
      // Allow updating description and permissions but not name for system roles
      if (name && name !== role.name) {
        return res.status(403).json({
          success: false,
          message: 'Cannot rename system roles (admin, user)'
        });
      }
    }
    
    // If name is being changed, check for duplicates
    if (name && name !== role.name) {
      const existingRole = await Role.findOne({ where: { name } });
      if (existingRole) {
        return res.status(400).json({
          success: false,
          message: 'Role with this name already exists'
        });
      }
    }
    
    // Update the role
    await role.update({
      name: name || role.name,
      description: description !== undefined ? description : role.description,
      permissions: permissions || role.permissions
    });
    
    console.log(`✅ Updated role: ${role.name}`);
    
    res.status(200).json({
      success: true,
      message: 'Role updated successfully',
      role
    });
  } catch (error) {
    console.error('❌ Error updating role:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while updating the role'
    });
  }
};

/**
 * Delete a role (admin only)
 */
const deleteRole = async (req, res) => {
  try {
    console.log(`🗑️ Deleting role with ID: ${req.params.id}`);
    
    // Find the role
    const role = await Role.findByPk(req.params.id);
    
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Role not found'
      });
    }
    
    // Check if the role being deleted is a protected system role
    if (role.name === 'admin' || role.name === 'user') {
      return res.status(403).json({
        success: false,
        message: 'Cannot delete system roles (admin, user)'
      });
    }
    
    // Delete the role
    await role.destroy();
    
    console.log(`✅ Deleted role: ${role.name}`);
    
    res.status(200).json({
      success: true,
      message: 'Role deleted successfully'
    });
  } catch (error) {
    console.error('❌ Error deleting role:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while deleting the role'
    });
  }
};

/**
 * Assign a role to a user (admin only)
 */
const assignRoleToUser = async (req, res) => {
  try {
    console.log('➕ Assigning role to user');
    const { userId, roleId } = req.body;
    
    // Check if user exists
    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Check if role exists
    const role = await Role.findByPk(roleId);
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Role not found'
      });
    }
    
    // Check if the user already has this role
    const existingAssignment = await UserRole.findOne({
      where: {
        userId,
        roleId
      }
    });
    
    if (existingAssignment) {
      return res.status(400).json({
        success: false,
        message: 'User already has this role'
      });
    }
    
    // Assign the role to the user
    await UserRole.create({
      userId,
      roleId,
      assignedBy: req.user.id, // Current admin's ID
      assignedAt: new Date()
    });
    
    console.log(`✅ Assigned role ${role.name} to user ${userId}`);
    
    res.status(200).json({
      success: true,
      message: `Role '${role.name}' assigned to user successfully`
    });
  } catch (error) {
    console.error('❌ Error assigning role:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while assigning the role'
    });
  }
};

/**
 * Remove a role from a user (admin only)
 */
const removeRoleFromUser = async (req, res) => {
  try {
    console.log('➖ Removing role from user');
    const { userId, roleId } = req.body;
    
    // Find the role assignment
    const userRole = await UserRole.findOne({
      where: {
        userId,
        roleId
      }
    });
    
    if (!userRole) {
      return res.status(404).json({
        success: false,
        message: 'User does not have this role'
      });
    }
    
    // Get role info for response
    const role = await Role.findByPk(roleId);
    
    // If this is the only admin role and we're removing it from the last admin user, prevent it
    if (role.name === 'admin') {
      const adminRoleId = role.id;
      const adminUsers = await UserRole.count({
        where: { roleId: adminRoleId }
      });
      
      if (adminUsers <= 1) {
        return res.status(403).json({
          success: false,
          message: 'Cannot remove the last admin role assignment'
        });
      }
    }
    
    // Remove the role from the user
    await userRole.destroy();
    
    console.log(`✅ Removed role ${role.name} from user ${userId}`);
    
    res.status(200).json({
      success: true,
      message: `Role '${role.name}' removed from user successfully`
    });
  } catch (error) {
    console.error('❌ Error removing role:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while removing the role'
    });
  }
};

/**
 * Get roles for a specific user (admin only)
 */
const getUserRoles = async (req, res) => {
  try {
    console.log(`🔍 Fetching roles for user ID: ${req.params.userId}`);
    
    // Check if user exists
    const user = await User.findByPk(req.params.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Get all roles for this user
    const roles = await user.getRoles({
      attributes: ['id', 'name', 'description', 'permissions'],
      through: {
        attributes: ['assignedAt']
      }
    });
    
    res.status(200).json({
      success: true,
      userId: user.id,
      username: user.username,
      roles
    });
  } catch (error) {
    console.error('❌ Error fetching user roles:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while fetching user roles'
    });
  }
};

/**
 * Get users with a specific role (admin only)
 */
const getUsersByRole = async (req, res) => {
  try {
    console.log(`🔍 Fetching users with role ID: ${req.params.roleId}`);
    
    // Check if role exists
    const role = await Role.findByPk(req.params.roleId);
    if (!role) {
      return res.status(404).json({
        success: false,
        message: 'Role not found'
      });
    }
    
    // Get all users with this role
    const users = await role.getUsers({
      attributes: ['id', 'username', 'registrationMethod', 'isVerified', 'lastLogin'],
      through: {
        attributes: ['assignedAt', 'assignedBy']
      }
    });
    
    res.status(200).json({
      success: true,
      roleId: role.id,
      roleName: role.name,
      users
    });
  } catch (error) {
    console.error('❌ Error fetching role users:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while fetching users with this role'
    });
  }
};

module.exports = {
  getAllRoles,
  getRoleById,
  createRole,
  updateRole,
  deleteRole,
  assignRoleToUser,
  removeRoleFromUser,
  getUserRoles,
  getUsersByRole
};