use std::{fmt::Display, str::FromStr};

use crate::Error;

/// Represents a UNC path (Universal Naming Convention).
///
/// More on [MSDN](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#unc-paths)
///
///
/// # Examples
/// ```
/// use smb::UncPath;
/// use std::str::FromStr;
/// let unc = UncPath::from_str(r"\\server\share\path").unwrap();
/// assert_eq!(unc.server, "server");
/// assert_eq!(unc.share, Some("share".to_string()));
/// assert_eq!(unc.path, Some("path".to_string()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UncPath {
    pub server: String,
    pub share: Option<String>,
    pub path: Option<String>,
}

impl UncPath {
    /// Creates a UNC path with the specified server.
    pub fn new(server: String) -> Self {
        UncPath {
            server,
            share: None,
            path: None,
        }
    }

    /// Creates a new [UncPath] with the IPC$ share,
    /// and with no path set.
    pub fn ipc_share(server: String) -> Self {
        const SMB_IPC_SHARE: &str = "IPC$";
        Self::new(server).with_share(SMB_IPC_SHARE.to_string())
    }

    /// Returns the current [UncPath] with a different share name.
    pub fn with_share(self, share: String) -> Self {
        UncPath {
            server: self.server,
            share: Some(share),
            path: self.path,
        }
    }

    /// Returns the current [UncPath] with a different path.
    pub fn with_path(self, path: String) -> Self {
        UncPath {
            server: self.server,
            share: self.share,
            path: Some(path),
        }
    }

    /// Returns the current [UncPath] with no path set.
    pub fn with_no_path(self) -> Self {
        UncPath {
            server: self.server,
            share: self.share,
            path: None,
        }
    }

    /// Adds to the current path, if set.
    /// Otherwise, sets the path to the new value.
    /// ```
    /// # use std::str::FromStr;
    /// # use smb::UncPath;
    /// let unc = UncPath::from_str(r"\\server\share\path").unwrap();
    /// let unc = unc.with_add_path("new_folder");
    /// assert_eq!(unc.to_string(), r"\\server\share\path\new_folder");
    /// ```
    pub fn with_add_path(mut self, add_path: &str) -> Self {
        if self.path.is_none() || self.path.as_ref().unwrap().is_empty() {
            self.path = Some(add_path.to_string());
            return self;
        }

        let path = self.path.as_ref().unwrap().trim_end_matches('\\');
        let add_path = add_path.trim_start_matches('\\');

        self.path = Some(format!("{}\\{}", path, add_path));
        self
    }
}

impl FromStr for UncPath {
    type Err = crate::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if !input.starts_with(r"\\") && !input.starts_with(r"//") {
            return Err(Error::InvalidArgument(
                "UNC path must start with two slashes/backslashes".to_string(),
            ));
        }
        let parts: Vec<&str> = input[2..].splitn(3, ['\\', '/']).collect();
        if parts.is_empty() {
            return Err(Error::InvalidArgument(
                "UNC path must include at least a server and tree name".to_string(),
            ));
        }
        Ok(UncPath {
            server: parts[0].to_string(),
            share: parts.get(1).map(|s| s.to_string()),
            path: parts.get(2).map(|s| s.to_string()),
        })
    }
}

impl Display for UncPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, r"\\{}", self.server)?;

        if let Some(share) = &self.share {
            write!(f, r"\{share}",)?;
        }

        if let Some(path) = &self.path {
            write!(f, r"\{path}",)?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_unc_path_parse() {
        let unc_full = UncPath {
            server: String::from("server"),
            share: Some(String::from("share")),
            path: Some(String::from("path")),
        };
        let unc_no_path = UncPath {
            server: String::from("server"),
            share: Some(String::from("share")),
            path: None,
        };
        let unc_no_share = UncPath {
            server: String::from("server"),
            share: None,
            path: None,
        };
        let paths = vec![
            (r"\\server\share\path", &unc_full),
            (r"//server/share/path", &unc_full),
            (r"\\server\share", &unc_no_path),
            (r"//server/share", &unc_no_path),
            (r"\\server", &unc_no_share),
            (r"//server", &unc_no_share),
        ];
        for (path, exp) in paths {
            assert_eq!(&UncPath::from_str(path).unwrap(), exp);
        }
    }

    #[test]
    fn test_unc_path_parse_invalid() {
        let invalid_paths = vec![r"a", r"\server", r"/server"];
        for path in invalid_paths {
            assert!(UncPath::from_str(path).is_err());
        }
    }

    #[test]
    fn test_unc_path_display() {
        let unc_full = UncPath {
            server: String::from("server33"),
            share: Some(String::from("share2")),
            path: Some(String::from("path/to/heaven")),
        }
        .to_string();
        assert_eq!(unc_full, r"\\server33\share2\path/to/heaven");
    }

    #[test]
    fn test_add_path() {
        // Random combinations
        let path = UncPath {
            server: String::from("server"),
            share: Some(String::from("share")),
            path: Some(String::from("path")),
        };
        for (p, r) in [
            ("", r"\\server\share\path\"),
            (r"\check", r"\\server\share\path\check"),
            (r"my", r"\\server\share\path\my"),
            (r"\dir\", r"\\server\share\path\dir\"),
        ] {
            assert_eq!(path.clone().with_add_path(p).to_string(), r);
        }
        // Empty path
        for empty_path in [
            UncPath {
                server: String::new(),
                share: None,
                path: None,
            },
            UncPath {
                server: String::new(),
                share: None,
                path: Some(String::new()),
            },
        ] {
            assert_eq!(
                empty_path.with_add_path("test").path,
                Some("test".to_string())
            );
        }
    }
}
