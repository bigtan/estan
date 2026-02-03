use crate::Result;

pub trait Notifier: Send + Sync {
    fn send(&self, subject: &str, message: &str) -> Result<bool>;
}

pub struct NotificationManager {
    services: Vec<Box<dyn Notifier>>,
}

impl NotificationManager {
    pub fn new() -> Self {
        Self {
            services: Vec::new(),
        }
    }

    pub fn add<N>(&mut self, notifier: N) -> &mut Self
    where
        N: Notifier + 'static,
    {
        self.services.push(Box::new(notifier));
        self
    }

    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    pub fn send(&self, subject: &str, message: &str) -> Result<bool> {
        if self.services.is_empty() {
            return Ok(false);
        }

        let mut success = false;
        for service in &self.services {
            if service.send(subject, message)? {
                success = true;
            }
        }
        Ok(success)
    }
}

impl Default for NotificationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "notify-chanify")]
pub mod chanify;

#[cfg(feature = "notify-email")]
pub mod email;

#[cfg(feature = "notify-pushgo")]
pub mod pushgo;

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeNotifier {
        succeed: bool,
    }

    impl Notifier for FakeNotifier {
        fn send(&self, _subject: &str, _message: &str) -> Result<bool> {
            Ok(self.succeed)
        }
    }

    #[test]
    fn manager_empty_returns_false() {
        let manager = NotificationManager::new();
        let ok = manager.send("sub", "msg").unwrap();
        assert!(!ok);
    }

    #[test]
    fn manager_aggregates_success() {
        let mut manager = NotificationManager::new();
        manager.add(FakeNotifier { succeed: false });
        manager.add(FakeNotifier { succeed: true });
        let ok = manager.send("sub", "msg").unwrap();
        assert!(ok);
    }
}
