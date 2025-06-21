use crate::Cli;
use clap::Parser;
#[cfg(feature = "async")]
use futures_util::StreamExt;
use maybe_async::*;
use smb::resource::{GetLen, ResourceHandle};
use smb::{
    packets::{fscc::*, smb2::AdditionalInfo},
    resource::{Directory, Resource},
    Client, FileCreateArgs, UncPath,
};
use std::{error::Error, sync::Arc};

#[derive(Parser, Debug)]
pub struct InfoCmd {
    /// The UNC path to the share, file, or directory to query.
    pub path: UncPath,

    #[arg(long)]
    pub show_security: bool,
}

#[maybe_async]
pub async fn info(cmd: &InfoCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    let mut client = Client::new(cli.make_smb_client_config());

    if cmd.path.share.is_none() || cmd.path.share.as_ref().unwrap().is_empty() {
        client
            .ipc_connect(&cmd.path.server, &cli.username, cli.password.clone())
            .await?;

        let ipc_share = UncPath::ipc_share(cmd.path.server.to_string());
        let tree = client.get_share(&ipc_share)?;
        let interfaces = tree.query_network_interfaces().await?;
        dbg!(interfaces);

        // let shares_info = client.list_shares(&cmd.path.server).await?;
        // log::info!("Available shares on {}: ", cmd.path.server);
        // for share in shares_info {
        //     log::info!("  - {}", **share.netname.as_ref().unwrap());
        // }
        return Ok(());
    }

    client
        .share_connect(&cmd.path, cli.username.as_ref(), cli.password.clone())
        .await?;
    let resource = client
        .create_file(
            &cmd.path,
            &FileCreateArgs::make_open_existing(FileAccessMask::new().with_generic_read(true)),
        )
        .await?;

    match resource {
        Resource::File(file) => {
            let info: FileBasicInformation = file.query_info().await?;
            let size_kb = file.get_len().await?.div_ceil(1024);
            log::info!("{}", cmd.path);
            log::info!("  - Size: ~{size_kb}kB");
            log::info!("  - Creation time: {}", info.creation_time);
            log::info!("  - Last write time: {}", info.last_write_time);
            log::info!("  - Last access time: {}", info.last_access_time);
            show_security_info(&file, cmd).await?;
        }
        Resource::Directory(dir) => {
            let dir = Arc::new(dir);
            log::info!("{}", cmd.path);
            iterate_directory(&dir, "*", |info| {
                match info.file_attributes.directory() {
                    true => log::info!("  - {} {}/", "(D)", info.file_name),
                    false => log::info!(
                        "  - {} {} ~{}kB",
                        "(F)",
                        info.file_name,
                        info.end_of_file.div_ceil(1024)
                    ),
                }
                Ok(())
            })
            .await?;
            show_security_info(&dir, cmd).await?;
        }
        Resource::Pipe(_) => {
            log::info!("Pipe (no information)");
        }
    };

    client.close().await?;

    Ok(())
}

#[maybe_async]
async fn show_security_info(resource: &ResourceHandle, cmd: &InfoCmd) -> smb::Result<()> {
    if !cmd.show_security {
        return Ok(());
    }

    let security = resource
        .query_security_info(AdditionalInfo::new().with_owner_security_information(true))
        .await?;
    log::info!("Security info: {security:?}");
    Ok(())
}

#[sync_impl]
fn iterate_directory(
    dir: &Arc<Directory>,
    pattern: &str,
    func: impl Fn(&FileIdBothDirectoryInformation) -> smb::Result<()>,
) -> smb::Result<()> {
    for info in Directory::query_directory::<FileIdBothDirectoryInformation>(dir, pattern)? {
        func(&info?)?;
    }
    Ok(())
}

#[async_impl]
async fn iterate_directory(
    dir: &Arc<Directory>,
    pattern: &str,
    func: impl Fn(&FileIdBothDirectoryInformation) -> smb::Result<()>,
) -> smb::Result<()> {
    let mut info_stream =
        Directory::query_directory::<FileIdBothDirectoryInformation>(dir, pattern).await?;
    while let Some(info) = info_stream.next().await {
        func(&info?)?;
    }
    Ok(())
}
