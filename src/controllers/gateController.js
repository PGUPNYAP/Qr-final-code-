const jwt = require("jsonwebtoken");
const QRPass = require("../models/QRPass");
const ScanLog = require("../models/ScanLog");
const AccessRequest = require("../models/AccessRequest");
const { updateUserActivity, checkAbusePattern } = require("../services/activityService");
const { checkRestriction, recordScanAttempt, applyRestriction } = require("../services/qrRotationService");
const HardwareToken = require("../models/HardwareToken");

const verifyQR = async (req, res) => {
  try {
    // ✅ FIX: req.body can be undefined from hardware requests
    const body = req.body || {};
    const { qrToken, gateId } = body;

    if (!qrToken || !gateId) {
      return res.status(400).json({
        status: "DENY",
        message: "qrToken and gateId required",
        state: null,
      });
    }

    // ✅ Verify JWT
    let decoded;
    try {
      decoded = jwt.verify(qrToken, process.env.JWT_SECRET);
    } catch (err) {
      return res.json({
        status: "DENY",
        message: "INVALID_SIGNATURE",
        state: null,
      });
    }

    // Map minified keys back to original variables (with fallback for legacy tokens)
    const { tId, rId, pTy, vF, vU } = decoded;
    const tokenId = tId || decoded.tokenId;
    const requestId = rId || decoded.requestId;
    const passType = pTy !== undefined ? (pTy === 1 ? "IN" : "OUT") : decoded.passType;
    const validFrom = vF ? new Date(vF * 1000) : decoded.validFrom;
    const validUntil = vU ? new Date(vU * 1000) : decoded.validUntil;

    if (!tokenId || !requestId || !passType) {
      return res.json({
        status: "DENY",
        message: "INVALID_QR_PAYLOAD",
        state: null,
      });
    }

    // ✅ Expiry check (JWT) - Check both validFrom and validUntil
    const now = new Date();

    if (validFrom && now < new Date(validFrom)) {
      await ScanLog.create({
        requestId,
        tokenId,
        passType,
        gateId,
        result: "DENY",
        reason: "QR_NOT_STARTED_YET",
      });

      return res.json({
        status: "DENY",
        message: "QR_NOT_STARTED_YET",
        state: null,
      });
    }

    if (validUntil && now > new Date(validUntil)) {
      await ScanLog.create({
        requestId,
        tokenId,
        passType,
        gateId,
        result: "DENY",
        reason: "QR_EXPIRED",
      });

      return res.json({
        status: "DENY",
        message: "QR_EXPIRED",
        state: null,
      });
    }

    // ✅ QRPass must exist
    const qrPass = await QRPass.findOne({
      tokenId,
      passType,
    });

    if (!qrPass) {
      await ScanLog.create({
        requestId,
        tokenId,
        passType,
        gateId,
        result: "DENY",
        reason: "PASS_NOT_FOUND",
      });

      return res.json({
        status: "DENY",
        message: "PASS_NOT_FOUND",
        state: null,
      });
    }

    // ✅ Fetch Access Request
    const request = await AccessRequest.findById(requestId);

    if (!request) {
      return res.json({
        status: "DENY",
        message: "USER_NOT_FOUND",
        state: null,
      });
    }

    if (request.status !== "APPROVED") {
      return res.json({
        status: "DENY",
        message: "NOT_APPROVED",
        state: request.currentState,
      });
    }

    // ✅ NEW: Enforce Validity Start + End (User Selected) - using 'now' from JWT check above

    if (request.validFrom && now < new Date(request.validFrom)) {
      return res.json({
        status: "DENY",
        message: "PASS_NOT_STARTED_YET",
        state: request.currentState,
      });
    }

    if (request.validUntil && now > new Date(request.validUntil)) {
      return res.json({
        status: "DENY",
        message: "PASS_EXPIRED",
        state: request.currentState,
      });
    }

    // ✅ CHECK FOR RESTRICTIONS (Anti-Abuse)
    const restrictionCheck = await checkRestriction(requestId);
    if (restrictionCheck.isRestricted) {
      await ScanLog.create({
        requestId,
        tokenId,
        passType,
        gateId,
        result: "DENY",
        reason: "USER_RESTRICTED",
      });

      return res.json({
        status: "DENY",
        message: "USER_RESTRICTED",
        restrictionUntil: restrictionCheck.until,
        state: request.currentState,
      });
    }

    // ✅ RECORD SCAN ATTEMPT
    const scanAttempt = await recordScanAttempt(requestId);
    if (scanAttempt.shouldRestrict) {
      await ScanLog.create({
        requestId,
        tokenId,
        passType,
        gateId,
        result: "DENY",
        reason: "TOO_MANY_ATTEMPTS",
      });

      return res.json({
        status: "DENY",
        message: "TOO_MANY_ATTEMPTS",
        state: request.currentState,
      });
    }

    // ✅ ENTRY
    if (passType === "IN") {
      if (request.currentState === "INSIDE") {
        return res.json({
          status: "DENY",
          message: "ALREADY_INSIDE",
          state: request.currentState,
        });
      }

      request.currentState = "INSIDE";
      await request.save();
    }

    // ✅ EXIT
    if (passType === "OUT") {
      if (request.currentState === "OUTSIDE") {
        return res.json({
          status: "DENY",
          message: "ALREADY_OUTSIDE",
          state: request.currentState,
        });
      }

      request.currentState = "OUTSIDE";
      await request.save();
    }

    // ✅ Log scan
    await ScanLog.create({
      requestId,
      tokenId,
      passType,
      gateId,
      result: "ALLOW",
      reason: null,
    });

    // ✅ UPDATE USER ACTIVITY
    await updateUserActivity(requestId, passType);

    // ✅ CHECK FOR ABUSE PATTERN
    const abuseCheck = await checkAbusePattern(requestId);
    if (abuseCheck.isAbuse) {
      await applyRestriction(requestId); // No hardcoded duration
    }

    return res.json({
      status: "ALLOW",
      message: passType === "IN" ? "ENTRY_GRANTED" : "EXIT_GRANTED",
      state: request.currentState,
      warning: abuseCheck.isAbuse ? "ABUSE_DETECTED" : null,
    });
  } catch (err) {
    console.log("VERIFY ERROR:", err.message);

    return res.status(500).json({
      status: "DENY",
      error: err.message,
      state: null,
    });
  }
};

// Helpers for token generation
const generateToken = () => {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let result = "";
  for (let i = 0; i < 7; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
};

/**
 * ✅ Handle Sync Request from Gate
 * GET /api/gate/sync/:deviceId (or POST)
 */
const syncTokens = async (req, res) => {
  try {
    const deviceId = req.params?.deviceId || req.body?.device_id || req.query?.deviceId || "GATE_01";
    
    // Ensure we have at least 50 UNASSIGNED tokens for THIS device
    const unassignedCount = await HardwareToken.countDocuments({ status: "UNASSIGNED", deviceId });
    const targetCount = 50;
    
    if (unassignedCount < targetCount) {
      const tokensToGenerate = targetCount - unassignedCount;
      const newTokens = [];
      for (let i = 0; i < tokensToGenerate; i++) {
        // Handle potential unique constraint collisions gracefully
        let success = false;
        let attempts = 0;
        while (!success && attempts < 3) {
          try {
            const tokenStr = generateToken();
            await HardwareToken.create({ token: tokenStr, status: "UNASSIGNED", deviceId });
            newTokens.push(tokenStr);
            success = true;
          } catch (e) {
            attempts++;
          }
        }
      }
    }
    
    // Fetch top 50 UNASSIGNED tokens for THIS device
    const tokens = await HardwareToken.find({ status: "UNASSIGNED", deviceId }).limit(50);
    const pool = tokens.map(t => t.token);
    
    return res.json({
      status: "success",
      device_id: deviceId,
      sync_count: pool.length,
      qr_pool: pool
    });
  } catch (err) {
    console.log("SYNC ERROR:", err.message);
    return res.status(500).json({ status: "error", message: err.message });
  }
};

/**
 * ✅ Handle Log Upload from Gate
 * POST /api/gate/logs
 * Body: { device_id: "...", logs: [{qr: "...", time: "..."}] }
 */
const uploadLogs = async (req, res) => {
  try {
    const { device_id, logs } = req.body || {};
    
    if (!logs || !Array.isArray(logs)) {
      return res.status(400).json({ status: "error", message: "Invalid logs payload" });
    }
    
    let processedCount = 0;
    
    for (const log of logs) {
      const { qr, time } = log;
      
      const tokenDoc = await HardwareToken.findOne({ token: qr });
      if (!tokenDoc) continue; // Unknown token scanned offline
      
      if (tokenDoc.status === "ASSIGNED" && tokenDoc.assignedTo) {
        // Found who this token belonged to
        const requestId = tokenDoc.assignedTo;
        const passType = tokenDoc.passType || "IN"; 
        
        // Find user 
        const user = await AccessRequest.findById(requestId);
        if (user) {
          // Update state (offline scan happened)
          if (passType === "IN" && user.currentState !== "INSIDE") {
            user.currentState = "INSIDE";
            await user.save();
          } else if (passType === "OUT" && user.currentState !== "OUTSIDE") {
            user.currentState = "OUTSIDE";
            await user.save();
          }
          
          // Log scan
          await ScanLog.create({
            requestId,
            tokenId: qr,
            passType,
            gateId: device_id || "GATE_01",
            result: "ALLOW",
            reason: "OFFLINE_SYNC"
            // Note: the original 'time' from hardware could be saved if ScanLog had a scanTime field
          });
          
          await updateUserActivity(requestId, passType);
        }
      }
      
      // Delete used/scanned token or mark USED
      await HardwareToken.deleteOne({ _id: tokenDoc._id });
      processedCount++;
    }
    
    // Replenish the pool with fresh tokens
    const newTokens = [];
    if (processedCount > 0) {
      for (let i = 0; i < processedCount; i++) {
        let success = false;
        let attempts = 0;
        while (!success && attempts < 3) {
          try {
            const tokenStr = generateToken();
            await HardwareToken.create({ token: tokenStr, status: "UNASSIGNED", deviceId: device_id || "GATE_01" });
            newTokens.push(tokenStr);
            success = true;
          } catch (e) {
            attempts++;
          }
        }
      }
    }
    
    return res.json({
      status: "synced",
      new_tokens: newTokens
    });
  } catch (err) {
    console.log("LOG UPLOAD ERROR:", err.message);
    return res.status(500).json({ status: "error", message: err.message });
  }
};

module.exports = { verifyQR, syncTokens, uploadLogs };
