<?php
// notify-admin.php

// Set your admin email
$adminEmail = "contact@ezmcyber.xyz";

// Get POST data
$data = json_decode(file_get_contents('php://input'), true);

if (!$data || !isset($data['message'])) {
    http_response_code(400);
    echo json_encode(["status" => "error", "message" => "Invalid request"]);
    exit;
}

$name = isset($data['name']) ? htmlspecialchars($data['name']) : "Unknown";
$email = isset($data['email']) ? htmlspecialchars($data['email']) : "Unknown";
$message = htmlspecialchars($data['message']);

// Email subject and body
$subject = "Live Support Request from $name";
$body = "You have a new Live Support request:\n\n";
$body .= "Name: $name\n";
$body .= "Email: $email\n";
$body .= "Message: $message\n";
$body .= "\n-- EZM Cyber";

// Email headers
$headers = "From: noreply@ezmcyber.xyz\r\n";
$headers .= "Reply-To: $email\r\n";

if (mail($adminEmail, $subject, $body, $headers)) {
    echo json_encode(["status" => "success", "message" => "Notification sent"]);
} else {
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Failed to send email"]);
}
?>