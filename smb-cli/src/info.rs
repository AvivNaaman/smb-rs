use crate::Cli;
use clap::{Parser, ValueEnum};
#[cfg(feature = "async")]
use futures_util::StreamExt;
use maybe_async::*;
use smb::resource::{GetLen, ResourceHandle};
use smb::{
    Client, FileCreateArgs, UncPath,
    packets::{fscc::*, smb2::AdditionalInfo},
    resource::{Directory, Resource},
};
use std::collections::VecDeque;
use std::fmt::Display;
use std::{error::Error, sync::Arc};

/// Recursion mode options
#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecursiveMode {
    /// Do not recurse into subdirectories
    #[default]
    NonRecursive,
    /// List all files and directories
    List,
}

impl Display for RecursiveMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecursiveMode::NonRecursive => write!(f, "non-recursive"),
            RecursiveMode::List => write!(f, "list"),
        }
    }
}

#[derive(Parser, Debug)]
pub struct InfoCmd {
    /// The UNC path to the share, file, or directory to query.
    pub path: UncPath,

    #[arg(long)]
    pub show_security: bool,

    /// Mode of recursion for directory listings
    #[arg(short, long)]
    #[clap(default_value_t = RecursiveMode::NonRecursive)]
    pub recursive: RecursiveMode,
}

#[maybe_async]
pub async fn info(cmd: &InfoCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    let client = Client::new(cli.make_smb_client_config());

    if cmd.path.share.is_none() || cmd.path.share.as_ref().unwrap().is_empty() {
        client
            .ipc_connect(&cmd.path.server, &cli.username, cli.password.clone())
            .await?;
        let shares_info = client.list_shares(&cmd.path.server).await?;
        log::info!("Available shares on {}: ", cmd.path.server);
        for share in shares_info {
            log::info!("  - {}", **share.netname.as_ref().unwrap());
        }
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
            file.close().await?;
        }
        Resource::Directory(dir) => {
            let dir = Arc::new(dir);
            iterate_directory(
                &dir,
                &cmd.path,
                "*",
                &IterateParams {
                    display_func: &display_item_info,
                    client: &client,
                    recursive: cmd.recursive,
                },
            )
            .await?;
            show_security_info(&dir, cmd).await?;
            dir.close().await?;
        }
        Resource::Pipe(p) => {
            log::info!("Pipe");
            p.close().await?;
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

type DisplayFunc = dyn Fn(&FileIdBothDirectoryInformation, &UncPath);

fn display_item_info(info: &FileIdBothDirectoryInformation, dir_path: &UncPath) {
    if info.file_name == "." || info.file_name == ".." {
        return; // Skip current and parent directory entries
    }

    match info.file_attributes.directory() {
        true => log::info!("  - {} {dir_path}/{}/", "(D)", info.file_name),
        false => log::info!(
            "  - {} {dir_path}/{} ~{}kB",
            "(F)",
            info.file_name,
            info.end_of_file.div_ceil(1024)
        ),
    }
}

struct IterateParams<'a> {
    display_func: &'a DisplayFunc,
    client: &'a Client,
    recursive: RecursiveMode,
}
struct IteratedItem {
    dir: Arc<Directory>,
    path: UncPath,
}

#[maybe_async]
async fn iterate_directory(
    dir: &Arc<Directory>,
    dir_path: &UncPath,
    pattern: &str,
    params: &IterateParams<'_>,
) -> smb::Result<()> {
    let mut subdirs = VecDeque::new();
    subdirs.push_back(IteratedItem {
        dir: Arc::clone(dir),
        path: dir_path.clone(),
    });

    while subdirs.front().is_some() {
        iterate_dir_items(&subdirs.pop_front().unwrap(), pattern, &mut subdirs, params).await?;

        assert!(params.recursive >= RecursiveMode::List || subdirs.is_empty())
    }
    Ok(())
}

#[async_impl]
async fn iterate_dir_items(
    item: &IteratedItem,
    pattern: &str,
    subdirs: &mut VecDeque<IteratedItem>,
    params: &IterateParams<'_>,
) -> smb::Result<()> {
    let mut info_stream =
        Directory::query::<FileIdBothDirectoryInformation>(&item.dir, pattern).await?;
    while let Some(info) = info_stream.next().await {
        if let Some(to_push) = handle_iteration_item(&info?, &item.path, params).await {
            subdirs.push_back(to_push);
        }
    }
    Ok(())
}

#[sync_impl]
fn iterate_dir_items(
    item: &IteratedItem,
    pattern: &str,
    subdirs: &mut VecDeque<IteratedItem>,
    params: &IterateParams<'_>,
) -> smb::Result<()> {
    for info in Directory::query::<FileIdBothDirectoryInformation>(&item.dir, pattern)? {
        if let Some(to_push) = handle_iteration_item(&info?, &item.path, params) {
            subdirs.push_back(to_push);
        }
    }
    Ok(())
}

#[maybe_async]
async fn handle_iteration_item(
    info: &FileIdBothDirectoryInformation,
    dir_path: &UncPath,
    params: &IterateParams<'_>,
) -> Option<IteratedItem> {
    (params.display_func)(info, dir_path);

    if params.recursive < RecursiveMode::List {
        return None;
    }

    if !info.file_attributes.directory() || info.file_name == "." || info.file_name == ".." {
        return None;
    }

    let path_of_subdir = dir_path.clone().with_add_path(&info.file_name.to_string());
    let dir_result = params
        .client
        .create_file(
            &path_of_subdir,
            &FileCreateArgs::make_open_existing(FileAccessMask::new().with_generic_read(true)),
        )
        .await;

    if let Err(e) = dir_result {
        log::warn!("Failed to open directory {}: {}", path_of_subdir, e);
        return None;
    }

    let dir: Result<Directory, _> = dir_result.unwrap().try_into();
    match dir {
        Ok(dir) => Some(IteratedItem {
            dir: Arc::new(dir),
            path: path_of_subdir,
        }),
        _ => {
            log::warn!(
                "Failed to convert resource to directory for {}",
                path_of_subdir,
            );
            None
        }
    }
}
