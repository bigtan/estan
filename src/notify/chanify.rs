use reqwest::blocking::Client;
use reqwest::header::CONTENT_TYPE;
use serde_json::json;
use tracing::{debug, error, info};

use crate::notify::Notifier;
use crate::Result;

pub struct ChanifyNotifier {
    url: String,
    token: String,
    client: Client,
}

impl ChanifyNotifier {
    pub fn new(url: String, token: String) -> Self {
        Self {
            url,
            token,
            client: Client::new(),
        }
    }
}

impl Notifier for ChanifyNotifier {
    fn send(&self, subject: &str, message: &str) -> Result<bool> {
        let payload = json!({
            "token": self.token,
            "title": subject,
            "text": message,
            "autocopy": 1,
            "sound": 1,
            "priority": 10,
            "interruptionlevel": 0,
        });

        debug!("Sending Chanify notification to: {}", self.url);

        match self
            .client
            .post(&self.url)
            .header(CONTENT_TYPE, "application/json; charset=utf-8")
            .json(&payload)
            .send()
        {
            Ok(response) => {
                if response.status().is_success() {
                    info!("Chanify notification sent: {}", subject);
                    Ok(true)
                } else {
                    error!("Failed to send Chanify notification: {}", response.status());
                    Ok(false)
                }
            }
            Err(e) => Err(e.into()),
        }
    }
}
