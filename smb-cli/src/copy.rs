use crate::{path::*, Cli};
use clap::Parser;
use maybe_async::*;
use smb::resource::*;
use std::error::Error;

#[cfg(feature = "sync")]
use std::{fs, io};
#[cfg(feature = "async")]
use tokio::{fs, io::AsyncWriteExt};

#[derive(Parser, Debug)]
pub struct CopyCmd {
    pub from: Path,
    pub to: Path,
}

#[cfg(feature = "sync")]
fn do_copy(from: File, mut to: fs::File) -> Result<(), Box<dyn Error>> {
    let mut buffered_reader = io::BufReader::with_capacity(32768, from);
    io::copy(&mut buffered_reader, &mut to)?;

    Ok(())
}

#[cfg(feature = "async")]
async fn do_copy(from: File, mut to: fs::File) -> Result<(), Box<dyn Error>> {
    let mut buffer = vec![0u8; 2usize.pow(20)];
    let mut pos = 0;

    // TODO: Make it parallel!
    loop {
        let bytes_read = from.read_block(&mut buffer, pos).await?;
        if bytes_read == 0 {
            break;
        }
        to.write_all(&buffer[..bytes_read]).await?;
        pos += bytes_read as u64;
    }

    Ok(())
}

#[maybe_async]
pub async fn copy(cmd: &CopyCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    {
        let (from, client) = match &cmd.from {
            Path::Local(_) => panic!("Local to local copy not supported"),
            Path::Remote(unc_path) => {
                let (client, _session, _tree, mut resource) =
                    unc_path.connect_and_open(cli).await?;
                (
                    resource
                        .take()
                        .ok_or("Source file not found")?
                        .unwrap_file(),
                    client,
                )
            }
        };

        let to: fs::File = match &cmd.to {
            Path::Local(path_buf) => fs::File::create(path_buf).await?,
            Path::Remote(_) => panic!("Remote to remote copy not supported"),
        };

        do_copy(from, to).await?;

        client
    }
    .close()
    .await?;

    Ok(())
}
