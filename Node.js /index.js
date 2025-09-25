const functions = require("firebase-functions");
const express = require("express");
const admin = require("firebase-admin");

admin.initializeApp();
const app = express();

app.get("/", (req, res) => {
  res.send("✅ Firebase Express backend is live");
});

exports.api = functions.https.onRequest(app);