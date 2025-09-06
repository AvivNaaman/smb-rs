use crate::{Cli, path::*};
use clap::Parser;
use maybe_async::*;
use smb::sync_helpers::*;
use smb::{Client, CreateOptions, FileAccessMask, FileAttributes, resource::*};
use std::error::Error;
#[cfg(not(feature = "async"))]
use std::fs;

#[cfg(feature = "async")]
use tokio::fs;

#[derive(Parser, Debug)]
pub struct CopyCmd {
    /// Force copy, overwriting existing file(s).
    #[arg(short, long)]
    pub force: bool,

    /// Source path
    pub from: Path,
    /// Destination path
    pub to: Path,
}

enum CopyFileValue {
    Local(Mutex<fs::File>),
    Remote(File),
}

struct CopyFile {
    path: Path,
    value: CopyFileValue,
}

impl CopyFile {
    #[maybe_async]
    async fn open(
        path: &Path,
        client: &Client,
        cli: &Cli,
        cmd: &CopyCmd,
        read: bool,
    ) -> Result<Self, smb::Error> {
        let value = match path {
            Path::Local(path_buf) => {
                let file = fs::OpenOptions::new()
                    .read(read)
                    .write(!read)
                    .create(!read)
                    .create_new(!read && !cmd.force)
                    .truncate(!read)
                    .open(path_buf)
                    .await?;
                CopyFileValue::Local(Mutex::new(file))
            }
            Path::Remote(unc_path) => {
                client
                    .share_connect(unc_path, cli.username.as_str(), cli.password.clone())
                    .await?;
                let create_args = if read {
                    FileCreateArgs::make_open_existing(
                        FileAccessMask::new().with_generic_read(true),
                    )
                } else if cmd.force {
                    FileCreateArgs::make_overwrite(
                        FileAttributes::new().with_archive(true),
                        CreateOptions::new(),
                    )
                } else {
                    FileCreateArgs::make_create_new(
                        FileAttributes::new().with_archive(true),
                        CreateOptions::new(),
                    )
                };
                let file = client
                    .create_file(unc_path, &create_args)
                    .await?
                    .unwrap_file();
                CopyFileValue::Remote(file)
            }
        };
        Ok(CopyFile {
            path: path.clone(),
            value,
        })
    }

    #[maybe_async]
    async fn copy_to(self, to: CopyFile) -> Result<(), smb::Error> {
        use CopyFileValue::*;
        match self.value {
            Local(from_local) => match to.value {
                Local(_) => unreachable!(),
                Remote(to_remote) => block_copy(from_local, to_remote, 16).await?,
            },
            Remote(from_remote) => match to.value {
                Local(to_local) => block_copy(from_remote, to_local, 16).await?,
                Remote(to_remote) => {
                    if to.path.as_remote().unwrap().server()
                        == self.path.as_remote().unwrap().server()
                        && to.path.as_remote().unwrap().share()
                            == self.path.as_remote().unwrap().share()
                    {
                        // Use server-side copy if both files are on the same server
                        to_remote.srv_copy(&from_remote).await?
                    } else {
                        block_copy(from_remote, to_remote, 8).await?
                    }
                }
            },
        }
        Ok(())
    }
}

#[maybe_async]
pub async fn copy(cmd: &CopyCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    if matches!(cmd.from, Path::Local(_)) && matches!(cmd.to, Path::Local(_)) {
        return Err("Copying between two local files is not supported".into());
    }

    let client = Client::new(cli.make_smb_client_config());
    let from = CopyFile::open(&cmd.from, &client, cli, cmd, true).await?;
    let to = CopyFile::open(&cmd.to, &client, cli, cmd, false).await?;
    from.copy_to(to).await?;

    Ok(())
}
