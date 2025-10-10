use crate::Cli;
use clap::Parser;
use maybe_async::*;
use smb::{Client, DirAccessMask, NotifyFilter, UncPath, resource::*};
use std::error::Error;

#[derive(Parser, Debug)]
pub struct WatchCmd {
    /// The UNC path to the share, file, or directory to query.
    pub path: UncPath,

    /// Whether to watch recursively in all subdirectories.
    #[arg(short, long, default_value_t = false)]
    pub recursive: bool,
}

#[maybe_async]
pub async fn watch(cmd: &WatchCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    if cmd.path.share().is_none() || cmd.path.share().unwrap().is_empty() {
        return Err("Path must include a share name".into());
    }

    let client = Client::new(cli.make_smb_client_config()?);
    client
        .share_connect(&cmd.path, &cli.username, cli.password.clone())
        .await?;

    let dir_resource = client
        .create_file(
            &cmd.path,
            &FileCreateArgs::make_open_existing(
                DirAccessMask::new().with_list_directory(true).into(),
            ),
        )
        .await?;

    let dir = dir_resource
        .as_dir()
        .ok_or("The specified path is not a directory")?;

    log::info!("Watching directory: {}", cmd.path);
    loop {
        let next_event = dir
            .watch(
                NotifyFilter::new()
                    .with_file_name(true)
                    .with_dir_name(true)
                    .with_last_write(true),
                cmd.recursive,
            )
            .await?;
        println!("Change detected: {:?}", next_event);
    }
}
