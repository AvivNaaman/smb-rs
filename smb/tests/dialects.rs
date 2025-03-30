use common::make_server_connection;
#[cfg(feature = "async")]
use futures_util::StreamExt;
use serial_test::serial;
use smb::{
    connection::EncryptionMode,
    packets::{
        fscc::*,
        smb2::{AdditionalInfo, CreateDisposition, Dialect},
    },
    resource::Directory,
};
use std::sync::Arc;
mod common;

macro_rules! basic_test {
    ([$dialect:ident], [$($encrypt_mode:ident),*]) => {
        $(
            paste::paste! {
                #[cfg(all(feature = "sign", feature = "encrypt"))]
                #[maybe_async::test(
                    feature = "sync",
                    async(feature = "async", test_log::test(tokio::test(flavor = "multi_thread")))
                )]
                #[serial]
                pub async fn [<test_smbint_ $dialect:lower _e $encrypt_mode:lower>]() -> Result<(), Box<dyn std::error::Error>> {
                    test_smb_integration_dialect_encrpytion_mode(Dialect::$dialect, EncryptionMode::$encrypt_mode).await
                }
            }
        )*
    };

    ([$($dialect:ident),*], $encrypt_modes:tt) => {
        $(
            basic_test!([$dialect],  $encrypt_modes);
        )*
    };

}

basic_test!([Smb030, Smb0302, Smb0311], [Disabled, Required]);
basic_test!([Smb0202, Smb021], [Disabled]);

#[maybe_async::maybe_async]
async fn test_smb_integration_dialect_encrpytion_mode(
    force_dialect: Dialect,
    encryption_mode: EncryptionMode,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!(
        "Testing with dialect: {:?}, enc? {:?}",
        force_dialect,
        encryption_mode
    );

    let (_smb, _session, tree) = make_server_connection("MyShare", None).await?;

    const TEST_FILE: &str = "test.txt";
    const TEST_DATA: &[u8] = b"Hello, World!";

    // Hello, World! > test.txt
    let security = {
        let file = tree
            .create_file(
                TEST_FILE,
                CreateDisposition::Create,
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_generic_write(true),
            )
            .await?
            .unwrap_file();

        file.write_block(TEST_DATA, 0).await?;

        // Query security info (owner only)
        file.query_security_info(AdditionalInfo::new().with_owner_security_information(true))
            .await?
    };

    if security.owner_sid.is_none() {
        return Err("No owner SID found".into());
    }

    // Query directory and make sure our file exists there:
    {
        let directory = tree
            .open_existing("", FileAccessMask::new().with_generic_read(true))
            .await?
            .unwrap_dir();
        let directory = Arc::new(directory);
        let ds =
            Directory::query_directory::<FileDirectoryInformation>(&directory, TEST_FILE).await?;
        let mut found = false;

        ds.for_each(|entry| {
            if entry.unwrap().file_name.to_string() == TEST_FILE {
                found = true;
            }
            async { () }
        })
        .await;

        if !found {
            return Err("File not found in directory".into());
        }

        // TODO: Complete Query quota info -- model + fix request encoding.
        // directory
        //     .query_quota_info(QueryQuotaInfo {
        //         return_single: false.into(),
        //         restart_scan: false.into(),
        //         get_quota_info_content: Some(vec![FileGetQuotaInformationInner {
        //             sid: security.owner_sid.unwrap(),
        //         }
        //         .into()]),
        //         sid: None,
        //     })
        //     .await?;
    }

    {
        let file = tree
            .open_existing(
                TEST_FILE,
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_delete(true),
            )
            .await?
            .unwrap_file();

        // So anyway it will be deleted at the end.
        file.set_file_info(FileDispositionInformation {
            delete_pending: true.into(),
        })
        .await?;

        let mut buf = [0u8; TEST_DATA.len() + 2];
        let read_length = file.read_block(&mut buf, 0, false).await?;
        assert_eq!(read_length, TEST_DATA.len());
        assert_eq!(&buf[..read_length], TEST_DATA);

        // Query file info.
        let all_info = file.query_info::<FileAllInformation>().await?;
        assert_eq!(
            all_info.name.file_name.to_string(),
            "\\".to_string() + TEST_FILE
        );

        // Query filesystem info.
        file.query_fs_info::<FileFsSizeInformation>().await?;

        assert_eq!(all_info.standard.end_of_file, TEST_DATA.len() as u64);
    }

    Ok(())
}
