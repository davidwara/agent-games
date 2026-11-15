"use strict";

// Vercel serverless entry for the Proof Gatekeeper agent.
// The agent logic lives in ../gatekeeper-agent.js (plain Node http handler,
// exported after a require.main guard). This file only adapts it to Vercel's
// (req, res) serverless signature. No secrets here — HMAC secret comes from
// the AGENT_GAMES_HMAC_SECRET env var set in the Vercel dashboard.
const handleRequest = require("../gatekeeper-agent.js");

module.exports = (req, res) => handleRequest(req, res);
