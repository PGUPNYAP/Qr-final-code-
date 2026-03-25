const express = require("express");
const router = express.Router();

const { verifyQR, syncTokens, uploadLogs } = require("../controllers/gateController");
const gateAuth = require("../middleware/gateAuth");

/**
 * ✅ Gate Verification API
 */
router.post("/verify", gateAuth, verifyQR);
router.get("/verify", (req, res) => {
  res.send("✅ Gate Verify Endpoint Live (POST only)");
});

/**
 * ✅ Gate Offline Sync APIs
 */
// router.post("/sync", gateAuth, syncTokens);
router.get("/sync", gateAuth, syncTokens); // Allow GET as well for easier hardware testing
router.post("/logs", gateAuth, uploadLogs);

module.exports = router;
