// server.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');

const fetch = require('node-fetch');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;





// =======================
// AI Chat route
// =======================
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.post('/api/chat', async (req, res) => {
    const { message, context } = req.body;

    if (!message) return res.status(400).json({ reply: 'Message is required' });

    try {
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                // ✅ BACKTICKS are required here
                'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: "gpt-4",
                messages: [
                    { role: "system", content: "You are a helpful assistant for EZM Cyber website users." },
                    ...(context || []),
                    { role: "user", content: message }
                ]
            })
        });

        const data = await response.json();
        const reply = data.choices?.[0]?.message?.content || "No response from AI";
        res.json({ reply });
    } catch (err) {
        console.error(err);
        res.status(500).json({ reply: "Error generating AI response" });
    }
});

app.get('/', (req, res) => res.send('EZM Cyber Backend is running!'));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));