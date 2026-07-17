use onionroute_gateway_protocol::flow::FlowController;
use onionroute_gateway_protocol::ProtocolError;

#[test]
fn stream_ids_are_monotonic_and_never_reused() {
    let mut flow = FlowController::new(1024, 1024, 2).unwrap();
    flow.open_local(1, 512).unwrap();
    flow.confirm_local_open(1, 512).unwrap();
    flow.reject_or_close(1).unwrap();
    assert!(matches!(
        flow.open_local(1, 512),
        Err(ProtocolError::InvalidStreamId)
    ));
    assert!(matches!(
        flow.open_local(2, 512),
        Err(ProtocolError::InvalidStreamId)
    ));
    flow.open_local(3, 512).unwrap();
}

#[test]
fn data_consumes_both_windows_and_backpressures() {
    let mut flow = FlowController::new(10, 10, 1).unwrap();
    flow.open_local(1, 6).unwrap();
    flow.confirm_local_open(1, 6).unwrap();
    flow.debit_send(1, 6).unwrap();
    assert!(matches!(
        flow.debit_send(1, 1),
        Err(ProtocolError::Backpressure)
    ));
    flow.receive_window_update(1, 2).unwrap();
    flow.receive_window_update(0, 2).unwrap();
    flow.debit_send(1, 2).unwrap();

    flow.debit_receive(1, 6).unwrap();
    assert!(matches!(
        flow.debit_receive(1, 1),
        Err(ProtocolError::FlowControlViolation)
    ));
}

#[test]
fn credit_cannot_overflow_hard_window() {
    let mut flow = FlowController::new(1024, 1024, 1).unwrap();
    flow.open_local(1, 1024).unwrap();
    flow.confirm_local_open(1, 4 * 1024 * 1024).unwrap();
    assert!(matches!(
        flow.receive_window_update(1, 1),
        Err(ProtocolError::FlowControlViolation)
    ));
}
