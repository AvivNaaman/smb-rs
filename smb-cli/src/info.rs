use crate::{path::*, Cli};
use clap::Parser;
use maybe_async::*;
use smb::{packets::smb2::QueryDirectoryInfo, resource::Resource};
use std::error::Error;
#[derive(Parser, Debug)]
pub struct InfoCmd {
    pub path: UncPath,
}

#[maybe_async]
pub async fn info(info: &InfoCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    {
        let (client, _session, _tree, mut resource) = info.path.connect_and_open(cli).await?;
        let resource = resource.take().ok_or("Resource not found")?;
        match resource {
            Resource::File(file) => {
                let info = file.query_info().await?;
                log::info!("File info: {:?}", info);
                let security = file.query_security_info().await?;
                log::info!("Security info: {:?}", security);
            }
            Resource::Directory(mut dir) => {
                for item in dir.query("*").await? {
                    match item {
                        QueryDirectoryInfo::IdBothDirectoryInformation(item) => {
                            log::info!(
                                "{} {}",
                                if item.file_attributes.directory() {
                                    "d"
                                } else {
                                    "f"
                                },
                                item.file_name,
                            );
                        }
                        _ => {
                            log::warn!("Unexpected item type");
                        }
                    }
                }
            }
        };

        client
    }
    .close()
    .await?;

    Ok(())
}
