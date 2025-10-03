import express from "express";
import admin from "firebase-admin";
import axios from "axios";

const app = express();
app.use(express.json());

// Initialize Firebase Admin (only once)
if (!admin.apps.length) {
  admin.initializeApp();
}

// Your endpoint logic
app.post("/api/check-link", async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: "URL is required" });
    }

    // Example VirusTotal call (replace with your real API call)
    // const response = await axios.post("https://www.virustotal.com/api/v3/urls", { url }, { headers: { "x-apikey": "YOUR_KEY" } });
    // For now, just return URL safe
    const result = { url, safe: true };

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default app;