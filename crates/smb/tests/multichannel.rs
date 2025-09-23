#![cfg(feature = "test-multichannel")]

mod common;
use common::*;
use serial_test::serial;

#[test_log::test(maybe_async::test(
    not(feature = "async"),
    async(feature = "async", tokio::test(flavor = "multi_thread"))
))]
#[serial]
async fn test_multichannel_connection() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = default_connection_config();
    config.multichannel.enabled = true;
    let (client, share_path) =
        make_server_connection(TestConstants::DEFAULT_SHARE, Some(config)).await?;

    Ok(())
}
