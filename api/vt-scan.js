export default async function handler(req, res) {
  const vtKey = process.env.VT_API_KEY; // VirusTotal key from Vercel
  const { url } = req.body;

  const response = await fetch(`https://www.virustotal.com/api/v3/urls`, {
    method: 'POST',
    headers: {
      'x-apikey': vtKey,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ url })
  });

  const data = await response.json();
  res.status(200).json(data);
}