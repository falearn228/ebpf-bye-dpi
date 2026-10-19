//! Загрузка и валидация профиля тем же парсером, что у демона,
//! плюс привязка ошибки к строке файла профиля.

use anyhow::{Context, Result};
use goodbyedpi_daemon::config::DpiConfig;
use goodbyedpi_daemon::profile::{self, Lint};
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct ProfileSource {
    /// Inline-строка (`-c`)
    pub inline: String,
    pub file: Option<PathBuf>,
}

impl ProfileSource {
    pub fn is_empty(&self) -> bool {
        self.inline.trim().is_empty() && self.file.is_none()
    }

    /// Склейка в том же порядке, что `load_merged_config` в демоне: файл, затем inline.
    pub fn merged(&self) -> Result<(String, Option<String>)> {
        let mut chunks = Vec::new();
        let mut file_text = None;
        if let Some(path) = &self.file {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read profile '{}'", path.display()))?;
            if !text.trim().is_empty() {
                chunks.push(text.clone());
            }
            file_text = Some(text);
        }
        if !self.inline.trim().is_empty() {
            chunks.push(self.inline.clone());
        }
        Ok((chunks.join("\n"), file_text))
    }
}

#[derive(Debug, Clone)]
pub struct Location {
    pub origin: String,
    pub line: usize,
    pub column: usize,
    pub text: String,
}

#[derive(Debug)]
pub struct Validation {
    pub config: Option<DpiConfig>,
    pub error: Option<String>,
    pub location: Option<Location>,
    pub lints: Vec<Lint>,
}

impl Validation {
    pub fn ok(&self) -> bool {
        self.error.is_none()
    }
}

pub fn validate(source: &ProfileSource) -> Validation {
    let (merged, file_text) = match source.merged() {
        Ok(v) => v,
        Err(e) => {
            return Validation {
                config: None,
                error: Some(format!("{:#}", e)),
                location: None,
                lints: Vec::new(),
            }
        }
    };

    match DpiConfig::parse(&merged) {
        Ok(config) => Validation {
            lints: profile::lint(&config),
            config: Some(config),
            error: None,
            location: None,
        },
        Err(e) => {
            let error = format!("{:#}", e);
            let location = locate_error(&error, source, file_text.as_deref());
            Validation {
                config: None,
                error: Some(error),
                location,
                lints: Vec::new(),
            }
        }
    }
}

/// Ошибки парсера цитируют токен в одинарных кавычках ('s1x');
/// ищем самый длинный такой фрагмент в исходных строках.
fn locate_error(error: &str, source: &ProfileSource, file_text: Option<&str>) -> Option<Location> {
    let mut quoted: Vec<&str> = error
        .split('\'')
        .skip(1)
        .step_by(2)
        .filter(|s| s.len() > 1)
        .collect();
    quoted.sort_by_key(|s| std::cmp::Reverse(s.len()));

    let mut origins: Vec<(String, &str)> = Vec::new();
    if let (Some(path), Some(text)) = (&source.file, file_text) {
        origins.push((path.display().to_string(), text));
    }
    if !source.inline.trim().is_empty() {
        origins.push(("-c".to_string(), source.inline.as_str()));
    }

    for needle in quoted {
        for (origin, text) in &origins {
            for (idx, line) in text.lines().enumerate() {
                if line.trim_start().starts_with('#') {
                    continue;
                }
                if let Some(col) = line.find(needle) {
                    return Some(Location {
                        origin: origin.clone(),
                        line: idx + 1,
                        column: col + 1,
                        text: line.to_string(),
                    });
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locates_bad_token_in_file() {
        let dir = std::env::temp_dir().join(format!("gdpi-profile-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.txt");
        std::fs::write(&path, "# comment\ns1\n-o1\n-Ax\n").unwrap();

        let v = validate(&ProfileSource {
            inline: String::new(),
            file: Some(path),
        });
        assert!(!v.ok());
        let loc = v.location.expect("location");
        assert_eq!(loc.line, 4);
        assert_eq!(loc.column, 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn valid_inline_profile() {
        let v = validate(&ProfileSource {
            inline: "s1 -o1 -Ar".into(),
            file: None,
        });
        assert!(v.ok());
        assert!(v.lints.is_empty());
    }
}
