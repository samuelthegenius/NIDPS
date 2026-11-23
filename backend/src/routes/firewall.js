const express = require('express');
const router = express.Router();
const firewallController = require('../controllers/firewallController');

// GET /api/blocked
router.get('/blocked', firewallController.getBlocked);

// POST /api/block
router.post('/block', firewallController.block);

// POST /api/unblock
router.post('/unblock', firewallController.unblock);

module.exports = router;
