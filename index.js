import express from "express";
import fetch from "node-fetch";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

// Step 1: Redirect to GitHub
app.get("/auth/github", (req, res) => {
  const state = Math.random().toString(36).substring(2);
  const codeVerifier = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
  req.session = {}; // simple placeholder, use proper session later
  req.session.state = state;
  req.session.codeVerifier = codeVerifier;

  const codeChallenge = codeVerifier; // for simplicity; you can hash it for PKCE S256
  const githubUrl = `https://github.com/login/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=user:email&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=plain`;

  res.redirect(githubUrl);
});

// Step 2: Callback route
app.get("/auth/github/callback", async (req, res) => {
  const { code, state } = req.query;

  // Verify state
  if (state !== req.session.state) return res.status(400).send("Invalid state");

  // Exchange code for token
  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
    },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: req.session.codeVerifier,
    }),
  });
  const tokenData = await tokenRes.json();
  const accessToken = tokenData.access_token;

  if (!accessToken) return res.status(400).send("Failed to get access token");

  // Fetch user info
  const userRes = await fetch("https://api.github.com/user", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const user = await userRes.json();

  // Redirect back to front-end
  res.redirect(`/home.html?name=${encodeURIComponent(user.login)}&avatar=${encodeURIComponent(user.avatar_url)}`);
});

app.listen(3000, () => console.log("Server running on port 3000"));