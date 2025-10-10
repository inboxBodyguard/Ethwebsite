import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import cors from "cors";
import bodyParser from "body-parser";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// Two VirusTotal API keys — you can add more if needed
const VIRUSTOTAL_KEYS = [
  process.env.VIRUSTOTAL_API_KEY_1,
  process.env.VIRUSTOTAL_API_KEY_2
];

// Rotate API keys if one hits the limit
let currentKeyIndex = 0;
function getNextApiKey() {
  const key = VIRUSTOTAL_KEYS[currentKeyIndex];
  currentKeyIndex = (currentKeyIndex + 1) % VIRUSTOTAL_KEYS.length;
  return key;
}

// 🔍 Main route: Link safety checker
app.post("/api/check-link", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "Missing URL" });

    const apiKey = getNextApiKey();
    const encodedUrl = Buffer.from(url).toString("base64");

    const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
      headers: { "x-apikey": apiKey },
      timeout: 20000 // 20 seconds max
    });

    res.json({
      status: "success",
      data: response.data
    });
  } catch (err) {
    console.error("❌ Error checking link:", err.message);
    res.status(500).json({
      error: "Backend timeout or VirusTotal API error",
      message: err.message
    });
  }
});

// Root route
app.get("/", (req, res) => {
  res.send("✅ EZM Cyber Link Checker Backend is running fine.");
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));