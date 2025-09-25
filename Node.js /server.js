import express from "express";
import fetch from "node-fetch";
import dotenv from "dotenv";
import bodyParser from "body-parser";

dotenv.config();

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json()); // in case you need JSON parsing

app.post("/verify", async (req, res) => {
  const token = req.body["g-recaptcha-response"];
  if (!token) {
    return res.status(400).send("Captcha missing");
  }

  const secret = process.env.RECAPTCHA_SECRET;
  if (!secret) {
    return res.status(500).send("Server configuration error");
  }

  const verifyURL = `https://www.google.com/recaptcha/api/siteverify?secret=${secret}&response=${token}`;

  try {
    const response = await fetch(verifyURL, { method: "POST" });
    const data = await response.json();
    if (data.success) {
      return res.status(200).send("Verified");
    } else {
      return res.status(400).send("Captcha failed");
    }
  } catch (err) {
    console.error("Verification error:", err);
    return res.status(500).send("Server error");
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));