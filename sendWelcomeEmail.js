const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

async function sendWelcomeEmail(toEmail, userName) {
  const msg = {
    to: toEmail,
    from: 'welcome@ezmcyber.xyz', // Verified sender
    subject: 'Welcome to EZM Cyber!',
    text: `Hi ${userName}, welcome to EZM Cyber. Thank you for signing up!`,
    html: `<strong>Hi ${userName}, welcome to EZM Cyber. Thank you for signing up!</strong>`,
  };

  try {
    await sgMail.send(msg);
    console.log(`Welcome email sent to ${toEmail}`);
  } catch (error) {
    console.error('Error sending email:', error);
  }
}

module.exports = sendWelcomeEmail;