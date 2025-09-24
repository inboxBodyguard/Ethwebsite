import express from 'express';
import fetch from 'node-fetch';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const __dirname = path.resolve();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Endpoint to call VirusTotal
app.post('/api/virustotal', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'Missing URL' });

  const apiKey = process.env.VT_API_KEY;

  try {
    // Encode URL
    const urlId = Buffer.from(url).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    
    // Check existing report
    let response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': apiKey }
    });

    if (response.status === 404) {
      // Submit new scan
      response = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ url })
      });

      const scanData = await response.json();
      const analysisId = scanData.data.id;

      // Poll for completion
      let completed = false, attempts = 0;
      while (!completed && attempts < 15) {
        await new Promise(r => setTimeout(r, 2000));
        response = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          headers: { 'x-apikey': apiKey }
        });
        const reportData = await response.json();
        if (reportData.data.attributes.status === 'completed') {
          completed = true;
          return res.json(reportData.data.attributes);
        }
        attempts++;
      }
      return res.status(202).json({ message: 'Analysis pending, try again shortly.' });
    }

    const data = await response.json();
    return res.json(data.data.attributes);

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));