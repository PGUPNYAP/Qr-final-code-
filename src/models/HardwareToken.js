const mongoose = require("mongoose");

const hardwareTokenSchema = new mongoose.Schema(
  {
    token: {
      type: String,
      required: true,
      unique: true,
    },
    deviceId: {
      type: String,
      default: "GATE_01",
      required: true,
    },
    status: {
      type: String,
      enum: ["UNASSIGNED", "ASSIGNED", "USED"],
      default: "UNASSIGNED",
    },
    assignedTo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "AccessRequest",
      default: null,
    },
    assignedAt: {
      type: Date,
      default: null,
    },
    passType: {
      type: String,
      enum: ["IN", "OUT"],
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("HardwareToken", hardwareTokenSchema);
