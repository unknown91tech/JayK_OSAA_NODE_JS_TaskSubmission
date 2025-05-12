const express = require('express');
const router = express.Router();
const { 
  getAllRoles,
  getRoleById,
  createRole,
  updateRole,
  deleteRole,
  assignRoleToUser,
  removeRoleFromUser,
  getUserRoles,
  getUsersByRole
} = require('../controllers/roleController');

const { 
  validateCreateRole,
  validateUpdateRole,
  validateAssignRole,
  validateRemoveRole
} = require('../middlewares/validation');

const { 
  authenticateToken,
  isAdmin
} = require('../middlewares/auth');

// All role routes require authentication
router.use(authenticateToken);

// All roles routes require admin privileges
router.use(isAdmin);

// Role management endpoints
router.get('/', getAllRoles);
router.get('/:id', getRoleById);
router.post('/', validateCreateRole, createRole);
router.put('/:id', validateUpdateRole, updateRole);
router.delete('/:id', deleteRole);

// User-role assignment endpoints
router.post('/assign', validateAssignRole, assignRoleToUser);
router.post('/remove', validateRemoveRole, removeRoleFromUser);
router.get('/user/:userId', getUserRoles);
router.get('/:roleId/users', getUsersByRole);

module.exports = router;