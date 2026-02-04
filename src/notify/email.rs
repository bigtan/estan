use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use tracing::{debug, error, info};

use crate::Result;
use crate::notify::Notifier;

pub struct EmailNotifier {
    sender: String,
    password: String,
    recipient: String,
    smtp_host: String,
    smtp_port: u16,
}

impl EmailNotifier {
    pub fn new(sender: String, password: String, recipient: String) -> Self {
        Self {
            sender,
            password,
            recipient,
            smtp_host: "smtp.qq.com".to_string(),
            smtp_port: 465,
        }
    }

    pub fn with_smtp(
        sender: String,
        password: String,
        recipient: String,
        smtp_host: String,
        smtp_port: u16,
    ) -> Self {
        Self {
            sender,
            password,
            recipient,
            smtp_host,
            smtp_port,
        }
    }

    pub fn send_html(&self, subject: &str, html_body: &str) -> Result<bool> {
        debug!("Building email message (HTML)");
        let email = match Message::builder()
            .from(self.sender.parse().unwrap())
            .to(self.recipient.parse().unwrap())
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body.to_string())
        {
            Ok(email) => email,
            Err(e) => return Err(e.into()),
        };

        let creds = Credentials::new(self.sender.clone(), self.password.clone());

        debug!("Connecting to SMTP server");
        let mailer = match SmtpTransport::relay(&self.smtp_host) {
            Ok(builder) => builder.credentials(creds).port(self.smtp_port).build(),
            Err(e) => return Err(e.into()),
        };

        match mailer.send(&email) {
            Ok(_) => {
                info!("Email notification sent: {}", subject);
                Ok(true)
            }
            Err(e) => {
                error!("Failed to send email notification: {:?}", e);
                Ok(false)
            }
        }
    }
}

impl Notifier for EmailNotifier {
    fn send(&self, subject: &str, message: &str) -> Result<bool> {
        debug!("Building email message (plain text)");
        let email = match Message::builder()
            .from(self.sender.parse().unwrap())
            .to(self.recipient.parse().unwrap())
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(message.to_string())
        {
            Ok(email) => email,
            Err(e) => return Err(e.into()),
        };

        let creds = Credentials::new(self.sender.clone(), self.password.clone());

        debug!("Connecting to SMTP server");
        let mailer = match SmtpTransport::relay(&self.smtp_host) {
            Ok(builder) => builder.credentials(creds).port(self.smtp_port).build(),
            Err(e) => return Err(e.into()),
        };

        match mailer.send(&email) {
            Ok(_) => {
                info!("Email notification sent: {}", subject);
                Ok(true)
            }
            Err(e) => {
                error!("Failed to send email notification: {:?}", e);
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use lettre::message::header::ContentType;

    #[test]
    fn send_builds_plain_text_body() {
        let body = "Line1\nLine2";
        let email = lettre::Message::builder()
            .from("sender@example.com".parse().unwrap())
            .to("to@example.com".parse().unwrap())
            .subject("Subject")
            .header(ContentType::TEXT_PLAIN)
            .body(body.to_string())
            .unwrap();
        let formatted = String::from_utf8(email.formatted().to_vec()).unwrap();
        let normalized = formatted.replace("\r\n", "\n");
        assert!(normalized.contains("Line1\nLine2"));
    }
}
