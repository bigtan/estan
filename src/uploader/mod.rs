use std::collections::HashMap;

use crate::Result;

pub trait Uploader: Send {
    fn name(&self) -> &str;
    fn upload(&mut self, file_path: &str, dest_path: &str) -> Result<bool>;
}

#[derive(Debug, Default, Clone)]
pub struct UploadContext {
    vars: HashMap<String, String>,
}

impl UploadContext {
    pub fn new() -> Self {
        Self {
            vars: HashMap::new(),
        }
    }

    pub fn with_date(date: impl Into<String>) -> Self {
        let mut ctx = Self::new();
        ctx.insert("date", date);
        ctx
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.vars.insert(key.into(), value.into());
    }

    pub fn expand(&self, template: &str) -> String {
        expand_placeholders(template, &self.vars)
    }
}

pub struct UploadManager {
    uploaders: Vec<(Box<dyn Uploader>, String)>,
}

impl UploadManager {
    pub fn new() -> Self {
        Self {
            uploaders: Vec::new(),
        }
    }

    pub fn add<U>(&mut self, uploader: U, dest_path: impl Into<String>) -> &mut Self
    where
        U: Uploader + 'static,
    {
        self.uploaders.push((Box::new(uploader), dest_path.into()));
        self
    }

    pub fn has_uploaders(&self) -> bool {
        !self.uploaders.is_empty()
    }

    pub fn upload_file(&mut self, file_path: &str, ctx: &UploadContext) -> Result<UploadResult> {
        let mut overall_success = true;
        let mut results = Vec::with_capacity(self.uploaders.len());

        for (uploader, dest_path) in &mut self.uploaders {
            let expanded_path = ctx.expand(dest_path);
            let success = uploader.upload(file_path, &expanded_path)?;
            let name = uploader.name().to_string();
            results.push((name, success));
            if !success {
                overall_success = false;
            }
        }

        Ok(UploadResult {
            overall_success,
            results,
        })
    }
}

impl Default for UploadManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct UploadResult {
    pub overall_success: bool,
    pub results: Vec<(String, bool)>,
}

fn expand_placeholders(template: &str, vars: &HashMap<String, String>) -> String {
    let mut output = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '{' {
            let mut key = String::new();
            while let Some(&next) = chars.peek() {
                chars.next();
                if next == '}' {
                    break;
                }
                key.push(next);
            }

            if key.is_empty() {
                output.push('{');
            } else if let Some(value) = vars.get(&key) {
                output.push_str(value);
            } else {
                output.push('{');
                output.push_str(&key);
                output.push('}');
            }
        } else {
            output.push(ch);
        }
    }

    output
}

#[cfg(feature = "uploader-baidu")]
pub mod baidu;

#[cfg(feature = "uploader-baidu")]
pub use baidu::BaiduPanUploader;

#[cfg(feature = "uploader-cloud189")]
pub mod cloud189;

#[cfg(feature = "uploader-cloud189")]
pub use cloud189::Cloud189Uploader;

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeUploader {
        name: String,
        uploads: Vec<(String, String)>,
        succeed: bool,
    }

    impl FakeUploader {
        fn new(name: &str, succeed: bool) -> Self {
            Self {
                name: name.to_string(),
                uploads: Vec::new(),
                succeed,
            }
        }
    }

    impl Uploader for FakeUploader {
        fn name(&self) -> &str {
            &self.name
        }

        fn upload(&mut self, file_path: &str, dest_path: &str) -> Result<bool> {
            self.uploads
                .push((file_path.to_string(), dest_path.to_string()));
            Ok(self.succeed)
        }
    }

    #[test]
    fn expand_placeholders_replaces_known_vars() {
        let mut ctx = UploadContext::new();
        ctx.insert("date", "20250203");
        ctx.insert("name", "backup");
        let out = ctx.expand("/data/{date}/{name}/");
        assert_eq!(out, "/data/20250203/backup/");
    }

    #[test]
    fn expand_placeholders_keeps_unknown_vars() {
        let ctx = UploadContext::new();
        let out = ctx.expand("/data/{missing}/");
        assert_eq!(out, "/data/{missing}/");
    }

    #[test]
    fn upload_manager_reports_results() {
        let mut manager = UploadManager::new();
        let mut ctx = UploadContext::new();
        ctx.insert("date", "20250203");

        manager.add(FakeUploader::new("A", true), "/x/{date}");
        manager.add(FakeUploader::new("B", false), "/y/{date}");

        let result = manager.upload_file("file.tar.zst", &ctx).unwrap();
        assert!(!result.overall_success);
        assert_eq!(result.results.len(), 2);
        assert_eq!(result.results[0].0, "A");
        assert_eq!(result.results[0].1, true);
        assert_eq!(result.results[1].0, "B");
        assert_eq!(result.results[1].1, false);
    }
}
