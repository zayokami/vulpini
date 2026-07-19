use crate::common::{BoxedStream, CoreError};

/// The single relay loop shared by every connection path.
///
/// `copy_bidirectional` already implements the correct half-close semantics:
/// when one side reaches EOF, the opposite write half is shut down while the
/// remaining direction keeps flowing until its own EOF. Per-protocol relay
/// loops are forbidden — wrap streams into `BoxedStream` and call this.
pub async fn relay(
    mut client: BoxedStream,
    mut upstream: BoxedStream,
) -> Result<(u64, u64), CoreError> {
    let (up, down) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok((up, down))
}
