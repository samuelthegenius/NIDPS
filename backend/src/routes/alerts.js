const express = require('express');
const router = express.Router();
const alertsController = require('../controllers/alertsController');

// GET /api/alerts - Paginated alerts list
router.get('/', alertsController.getAlerts);

module.exports = router;
