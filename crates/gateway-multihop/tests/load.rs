use onionroute_gateway_multihop::mux::{FairMuxQueue, OutboundCommand};
use onionroute_gateway_multihop::ErrorCode;

#[test]
fn ten_thousand_producers_cannot_exceed_queue_budget() {
    let maximum = 4 * 1024 * 1024;
    let mut queue = FairMuxQueue::new(maximum, 64 * 1024, 256).unwrap();
    let payload = vec![0u8; 32 * 1024];
    let mut backpressured = 0usize;
    for index in 0..10_000u64 {
        let session_id = index.saturating_mul(2).saturating_add(1);
        match queue.try_push(OutboundCommand::Data {
            session_id,
            payload: payload.clone(),
        }) {
            Ok(()) => assert!(queue.queued_bytes() <= maximum),
            Err(error) => {
                assert_eq!(error.code, ErrorCode::Backpressure);
                backpressured += 1;
            }
        }
    }
    assert!(backpressured > 0);
    while queue.pop_next().is_some() {
        assert!(queue.queued_bytes() <= maximum);
    }
    assert_eq!(queue.queued_bytes(), 0);
}
