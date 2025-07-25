#![cfg(not(feature = "single_threaded"))]
use serial_test::serial;
use smb::{
    ConnectionConfig, FileCreateArgs,
    connection::EncryptionMode,
    packets::{fscc::*, smb2::NotifyFilter},
    resource::Resource,
    sync_helpers::*,
};
use std::sync::Arc;
mod common;

use common::TestConstants;
use common::make_server_connection;
const NEW_FILE_NAME_UNDER_WORKDIR: &str = "test_file.txt";

#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn test_smb_notify() -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, share_path) = make_server_connection(
        TestConstants::DEFAULT_SHARE,
        ConnectionConfig {
            encryption_mode: EncryptionMode::Disabled,
            ..Default::default()
        }
        .into(),
    )
    .await?;

    // Create the file
    {
        client
            .create_file(
                &share_path
                    .clone()
                    .with_path(NEW_FILE_NAME_UNDER_WORKDIR.to_string()),
                &FileCreateArgs::make_create_new(Default::default(), Default::default()),
            )
            .await?;
    }

    let dir = client
        .create_file(
            &share_path,
            &FileCreateArgs::make_open_existing(
                DirAccessMask::new().with_list_directory(true).into(),
            ),
        )
        .await?;

    let notified_sem = Arc::new(Semaphore::new(0));
    start_notify_task(notified_sem.clone(), dir);
    // Launch tasks to wait for notifications.
    // Another connection now modifying the file...
    delete_file_from_another_connection(TestConstants::DEFAULT_SHARE).await?;
    // Wait for notifiactions to arrive.
    let _p = notified_sem.acquire().await?;
    Ok(())
}

#[maybe_async::async_impl]
fn start_notify_task(sem: Arc<Semaphore>, r: Resource) {
    let filter = NotifyFilter::new()
        .with_file_name(true)
        .with_dir_name(true)
        .with_attributes(true)
        .with_last_write(true)
        .with_last_access(true);
    tokio::spawn(async move {
        for notification in r.unwrap_dir().watch(filter, true).await.unwrap() {
            if notification.action == NotifyAction::Removed {
                sem.add_permits(1);
                break;
            }
        }
    });
}
#[maybe_async::sync_impl]
fn start_notify_task(sem: Arc<Semaphore>, r: Resource) {
    let filter = NotifyFilter::new()
        .with_file_name(true)
        .with_dir_name(true)
        .with_attributes(true)
        .with_last_write(true)
        .with_last_access(true);
    std::thread::spawn(move || {
        for notification in r.unwrap_dir().watch(filter, true).unwrap() {
            if notification.action == NotifyAction::Removed {
                sem.add_permits(1);
                break;
            }
        }
    });
}
#[maybe_async::maybe_async]
async fn delete_file_from_another_connection(
    share_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, share_path) = make_server_connection(
        share_name,
        ConnectionConfig {
            encryption_mode: EncryptionMode::Disabled,
            ..Default::default()
        }
        .into(),
    )
    .await?;

    let file = client
        .create_file(
            &share_path.with_path(NEW_FILE_NAME_UNDER_WORKDIR.to_string()),
            &FileCreateArgs::make_open_existing(
                FileAccessMask::new()
                    .with_delete(true)
                    .with_generic_read(true),
            ),
        )
        .await?
        .unwrap_file();

    file.set_file_info(FileDispositionInformation {
        delete_pending: true.into(),
    })
    .await?;

    // We are exiting, and file is closed, and deleted!
    Ok(())
}
