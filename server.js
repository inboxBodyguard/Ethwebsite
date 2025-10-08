const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const sgMail = require('@sendgrid/mail');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Signup route
app.post('/signup', async (req, res) => {
    const { email, name } = req.body;

    if (!email) return res.status(400).json({ error: 'Email is required' });

    try {
        const msg = {
            to: email,
            from: process.env.FROM_EMAIL,
            subject: 'Welcome to EZM Cyber!',
            html: `
                <h2>Welcome to EZM Cyber, ${name || 'User'}!</h2>
                <p>Thank you for signing up. Your digital security journey starts now.</p>
                <p>– EZM Cyber Team</p>
            `
        };
        await sgMail.send(msg);

        return res.status(200).json({ message: 'Signup successful, email sent!' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Failed to send email' });
    }
});

// Health check
app.get('/', (req, res) => res.send('EZM Cyber Backend is running!'));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));