use log::info;
use serial_test::serial;
use smb::{
    packets::smb2::{CreateDisposition, Dialect, FileAccessMask},
    Connection, ConnectionConfig,
};
use std::env::var;

macro_rules! parametrize_dialect {
    ($($dialect:ident),*) => {
        $(
            paste::paste! {
                #[maybe_async::test(
                    feature = "sync",
                    async(feature = "async", tokio::test(flavor = "multi_thread"))
                )]
                #[serial]
                pub async fn [<test_smb_integration_ $dialect:lower>]() -> Result<(), Box<dyn std::error::Error>> {
                    test_smb_integration_basic(Dialect::$dialect).await
                }
            }
        )*
    };
}

parametrize_dialect!(Smb0302, Smb0311);

#[maybe_async::maybe_async]
pub async fn test_smb_integration_basic(
    force_dialect: Dialect,
) -> Result<(), Box<dyn std::error::Error>> {
    use smb::packets::smb2::FileDispositionInformation;

    let mut smb = Connection::new(ConnectionConfig {
        min_dialect: Some(force_dialect),
        max_dialect: Some(force_dialect),
        ..Default::default()
    });
    smb.set_timeout(Some(std::time::Duration::from_secs(10)))
        .await?;
    // Default to localhost, LocalAdmin, 123456
    let server = var("SMB_RUST_TESTS_SERVER").unwrap_or("127.0.0.1:445".to_string());
    let user = var("SMB_RUST_TESTS_USER_NAME").unwrap_or("LocalAdmin".to_string());
    let password = var("SMB_RUST_TESTS_PASSWORD").unwrap_or("123456".to_string());

    info!("Connecting to {} as {}", server, user);

    // Connect & Authenticate
    smb.connect(&server).await?;
    info!("Connected, authenticating...");
    let mut session = smb.authenticate(&user, password).await?;
    info!("Authenticated!");

    // String before ':', after is port:
    let server_name = server.split(':').next().unwrap();
    let mut tree = session
        .tree_connect(format!("\\\\{}\\MyShare", server_name).as_str())
        .await?;
    info!("Connected to share, start test basic");

    // Hello, World! > test.txt
    {
        let mut file = tree
            .create(
                "test.txt",
                CreateDisposition::Create,
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_generic_write(true),
            )
            .await?
            .unwrap_file();

        file.write(b"Hello, World!").await?;
    }

    {
        let file = tree
            .create(
                "test.txt",
                CreateDisposition::Open,
                FileAccessMask::new()
                    .with_generic_read(true)
                    .with_delete(true),
            )
            .await?
            .unwrap_file();

        let mut buf = [0u8; 15];
        let read_length = file.read_block(&mut buf, 0).await?;
        assert_eq!(read_length, 13);
        assert_eq!(&buf[..13], b"Hello, World!");
        file.set_file_info(FileDispositionInformation {
            delete_pending: true.into(),
        })
        .await?;
    }

    Ok(())
}
