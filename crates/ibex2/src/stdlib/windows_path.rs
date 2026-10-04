//! @ref LLP 0068#proposed-windows-native-filesystem-grants — one disjoint drive namespace.
use super::windows_directory::{refuse, validate_name};
use std::io;

#[derive(Clone, Debug)]
pub(crate) struct NativePath {
    pub drive: u8,
    pub parts: Vec<String>,
}
impl NativePath {
    pub fn parse(path: &str, normalize: bool) -> io::Result<Self> {
        let path = path.strip_prefix(r"\\?\").unwrap_or(path);
        let bytes = path.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || !matches!(bytes[2], b'/' | b'\\')
        {
            return Err(refuse("path must be a fully qualified local drive path"));
        }
        let mut parts = Vec::new();
        for part in path[3..].split(['/', '\\']) {
            match part {
                "" => continue,
                "." if normalize => continue,
                ".." if normalize => {
                    if parts.pop().is_none() {
                        return Err(refuse("path escapes its drive root"));
                    }
                }
                _ => {
                    if part.chars().any(char::is_control) {
                        return Err(refuse("native filesystem names cannot contain controls"));
                    }
                    validate_name(part)?;
                    parts.push(part.to_owned());
                }
            }
        }
        Ok(Self {
            drive: bytes[0].to_ascii_uppercase(),
            parts,
        })
    }
    pub fn spelling(&self) -> String {
        self.prefix(self.parts.len())
    }
    pub fn prefix(&self, length: usize) -> String {
        format!("{}:/{}", self.drive as char, self.parts[..length].join("/"))
    }
    pub fn grant_components(self) -> Vec<String> {
        let mut result = vec![format!("win:{}", self.drive as char)];
        result.extend(self.parts);
        result
    }
}
