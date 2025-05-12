
// scripts/healthCheck.js
const axios = require('axios');
require('dotenv').config();

const healthCheck = async () => {
  const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
  
  try {
    console.log('🏥 Performing health check...');
    
    // Check main health endpoint
    const response = await axios.get(`${baseUrl}/health`);
    console.log('✅ Health check passed:', response.data);
    
    // Check API endpoint
    const apiResponse = await axios.get(`${baseUrl}/api`);
    console.log('✅ API documentation accessible');
    
    // Check database connectivity (via auth endpoint)
    try {
      await axios.post(`${baseUrl}/api/auth/login`, {
        username: 'nonexistent',
        passcode: 'test',
        loginMethod: 'direct'
      });
    } catch (error) {
      if (error.response && error.response.status === 401) {
        console.log('✅ Database connectivity confirmed');
      } else {
        throw error;
      }
    }
    
    console.log('✅ All health checks passed');
    process.exit(0);
  } catch (error) {
    console.error('❌ Health check failed:', error.message);
    process.exit(1);
  }
};

healthCheck();