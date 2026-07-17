#![allow(unsafe_code)]
//! Stable, panic-contained C ABI for OnionRoute mobile runtimes.
//!
//! This is an experimental adapter. It deliberately has no direct-network
//! fallback and does not claim that a protected core exists until the platform
//! explicitly confirms it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};

use onionroute_client_core::ShutdownCoordinator;

pub const OR_STATUS_OK: i32 = 0;
pub const OR_STATUS_EMPTY: i32 = 1;
pub const OR_STATUS_INVALID_ARGUMENT: i32 = -1;
pub const OR_STATUS_INVALID_HANDLE: i32 = -2;
pub const OR_STATUS_INCOMPATIBLE_VERSION: i32 = -3;
pub const OR_STATUS_SHUTTING_DOWN: i32 = -4;
pub const OR_STATUS_INVALID_STATE: i32 = -5;
pub const OR_STATUS_BACKPRESSURE: i32 = -6;
pub const OR_STATUS_CANCELLED: i32 = -7;
pub const OR_STATUS_UNAVAILABLE: i32 = -8;
pub const OR_STATUS_PANIC: i32 = -127;

const ABI_MAJOR: u16 = 1;
const ABI_MINOR: u16 = 0;
const MIN_EVENT_CAPACITY: usize = 8;
const MAX_EVENT_CAPACITY: usize = 4096;
const MIN_MEMORY_BUDGET: u64 = 4 * 1024 * 1024;
const MAX_MEMORY_BUDGET: u64 = 256 * 1024 * 1024;
const MAX_PACKET_BYTES: usize = 128 * 1024;

const EVENT_ABI_NEGOTIATED: u32 = 1;
const EVENT_STATE_CHANGED: u32 = 2;
const EVENT_PLATFORM_ACTION: u32 = 3;
const EVENT_OPERATION: u32 = 4;
const EVENT_DIAGNOSTIC: u32 = 5;
const EVENT_QUEUE_OVERFLOW: u32 = 6;

const ACTION_APPLY_KILL_SWITCH: u64 = 1;
const ACTION_START_PROTECTED_CORE: u64 = 2;
const ACTION_STOP_PROTECTED_CORE: u64 = 3;
const ACTION_REFRESH_TOKEN: u64 = 4;
const ACTION_REFRESH_SIGNED_CONFIG: u64 = 5;

const DIAGNOSTIC_NETWORK_UNAVAILABLE: i32 = 1001;
const DIAGNOSTIC_CAPTIVE_PORTAL: i32 = 1002;
const DIAGNOSTIC_PACKET_CORE_UNAVAILABLE: i32 = 1003;
const DIAGNOSTIC_PROTECTED_PATH_UNHEALTHY: i32 = 1004;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OrCreateOptions {
    pub struct_size: u32,
    pub abi_min_major: u16,
    pub abi_min_minor: u16,
    pub abi_max_major: u16,
    pub abi_max_minor: u16,
    pub event_capacity: u32,
    pub memory_budget_bytes: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrEvent {
    pub struct_size: u32,
    pub kind: u32,
    pub sequence: u64,
    pub operation_id: u64,
    pub code: i32,
    pub data_len: u32,
    pub value: u64,
    pub data: [u8; 64],
}

impl Default for OrEvent {
    fn default() -> Self {
        Self {
            struct_size: std::mem::size_of::<Self>() as u32,
            kind: 0,
            sequence: 0,
            operation_id: 0,
            code: 0,
            data_len: 0,
            value: 0,
            data: [0; 64],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
enum State {
    Disconnected = 0,
    Preparing = 1,
    ApplyingKillSwitch = 2,
    BootstrappingTor = 3,
    Connected = 4,
    Rotating = 5,
    Reconnecting = 6,
    Blocked = 7,
    Disconnecting = 8,
}

#[derive(Debug)]
struct Inner {
    state: State,
    events: VecDeque<OrEvent>,
    event_capacity: usize,
    next_sequence: u64,
    next_operation: u64,
    active_operations: HashSet<u64>,
    country: Option<[u8; 2]>,
    anonymity_mode: u32,
    suspended_at_ms: Option<u64>,
    packet_unavailable_reported: bool,
    shutdown: ShutdownCoordinator,
}

impl Inner {
    fn new(event_capacity: usize) -> Self {
        Self {
            state: State::Disconnected,
            events: VecDeque::with_capacity(event_capacity),
            event_capacity,
            next_sequence: 1,
            next_operation: 1,
            active_operations: HashSet::new(),
            country: None,
            anonymity_mode: 0,
            suspended_at_ms: None,
            packet_unavailable_reported: false,
            shutdown: ShutdownCoordinator::default(),
        }
    }

    fn next_operation(&mut self) -> u64 {
        let operation = self.next_operation;
        self.next_operation = self.next_operation.wrapping_add(1).max(1);
        self.active_operations.insert(operation);
        operation
    }

    fn event(&mut self, kind: u32, operation_id: u64, code: i32, value: u64, data: &[u8]) {
        if self.events.len() + 2 > self.event_capacity {
            while self.events.len() > self.event_capacity.saturating_sub(2) {
                self.events.pop_front();
            }
            let overflow = self.make_event(EVENT_QUEUE_OVERFLOW, 0, OR_STATUS_BACKPRESSURE, 0, &[]);
            self.events.push_back(overflow);
        }
        let event = self.make_event(kind, operation_id, code, value, data);
        self.events.push_back(event);
    }

    fn make_event(
        &mut self,
        kind: u32,
        operation_id: u64,
        code: i32,
        value: u64,
        data: &[u8],
    ) -> OrEvent {
        let mut event = OrEvent {
            kind,
            sequence: self.next_sequence,
            operation_id,
            code,
            value,
            ..OrEvent::default()
        };
        self.next_sequence = self.next_sequence.wrapping_add(1).max(1);
        let copy_len = data.len().min(event.data.len());
        event.data[..copy_len].copy_from_slice(&data[..copy_len]);
        event.data_len = copy_len as u32;
        event
    }

    fn set_state(&mut self, state: State, operation_id: u64) {
        self.state = state;
        self.event(
            EVENT_STATE_CHANGED,
            operation_id,
            OR_STATUS_OK,
            state as u64,
            &[],
        );
    }

    fn finish_operation(&mut self, operation_id: u64, code: i32) {
        self.active_operations.remove(&operation_id);
        self.event(EVENT_OPERATION, operation_id, code, 0, &[]);
    }
}

#[derive(Debug, Default)]
struct Lifecycle {
    shutting_down: bool,
    active_calls: usize,
}

#[derive(Debug)]
struct Client {
    inner: Mutex<Inner>,
    lifecycle: Mutex<Lifecycle>,
    idle: Condvar,
}

struct CallGuard {
    client: Arc<Client>,
}

impl Drop for CallGuard {
    fn drop(&mut self) {
        let mut lifecycle = lock(&self.client.lifecycle);
        lifecycle.active_calls = lifecycle.active_calls.saturating_sub(1);
        if lifecycle.active_calls == 0 {
            self.client.idle.notify_all();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn registry() -> &'static Mutex<HashMap<u64, Arc<Client>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u64, Arc<Client>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_handle() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed).max(1)
}

fn begin_call(handle: u64) -> Result<CallGuard, i32> {
    let client = lock(registry())
        .get(&handle)
        .cloned()
        .ok_or(OR_STATUS_INVALID_HANDLE)?;
    {
        let mut lifecycle = lock(&client.lifecycle);
        if lifecycle.shutting_down {
            return Err(OR_STATUS_SHUTTING_DOWN);
        }
        lifecycle.active_calls += 1;
    }
    Ok(CallGuard { client })
}

fn ffi_boundary(body: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(OR_STATUS_PANIC)
}

fn validate_options(options: OrCreateOptions) -> Result<usize, i32> {
    if options.struct_size as usize != std::mem::size_of::<OrCreateOptions>() {
        return Err(OR_STATUS_INVALID_ARGUMENT);
    }
    if options.abi_min_major != ABI_MAJOR
        || options.abi_max_major != ABI_MAJOR
        || options.abi_min_minor != ABI_MINOR
        || options.abi_min_minor > options.abi_max_minor
    {
        return Err(OR_STATUS_INCOMPATIBLE_VERSION);
    }
    let event_capacity = options.event_capacity as usize;
    if !(MIN_EVENT_CAPACITY..=MAX_EVENT_CAPACITY).contains(&event_capacity)
        || !(MIN_MEMORY_BUDGET..=MAX_MEMORY_BUDGET).contains(&options.memory_budget_bytes)
    {
        return Err(OR_STATUS_INVALID_ARGUMENT);
    }
    Ok(event_capacity)
}

#[no_mangle]
/// Creates a process-local client token.
///
/// # Safety
/// `options` must be readable and `out_handle` writable for this call.
pub unsafe extern "C" fn or_client_create(
    options: *const OrCreateOptions,
    out_handle: *mut u64,
) -> i32 {
    ffi_boundary(|| {
        if options.is_null() || out_handle.is_null() {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: The C contract requires both pointers to reference initialized,
        // correctly aligned values for the duration of this call.
        let options = unsafe { *options };
        let event_capacity = match validate_options(options) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let mut inner = Inner::new(event_capacity);
        inner.event(
            EVENT_ABI_NEGOTIATED,
            0,
            OR_STATUS_OK,
            ((ABI_MAJOR as u64) << 32) | ABI_MINOR as u64,
            &[],
        );
        let client = Arc::new(Client {
            inner: Mutex::new(inner),
            lifecycle: Mutex::new(Lifecycle::default()),
            idle: Condvar::new(),
        });
        let handle = next_handle();
        lock(registry()).insert(handle, client);
        // SAFETY: Validated non-null above; the caller owns this output slot.
        unsafe { *out_handle = handle };
        OR_STATUS_OK
    })
}

#[no_mangle]
pub extern "C" fn or_client_destroy(handle: u64) -> i32 {
    ffi_boundary(|| {
        if handle == 0 {
            return OR_STATUS_INVALID_HANDLE;
        }
        let client = match lock(registry()).remove(&handle) {
            Some(client) => client,
            None => return OR_STATUS_INVALID_HANDLE,
        };
        let mut lifecycle = lock(&client.lifecycle);
        lifecycle.shutting_down = true;
        while lifecycle.active_calls != 0 {
            lifecycle = client
                .idle
                .wait(lifecycle)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        drop(lifecycle);

        let mut inner = lock(&client.inner);
        inner.shutdown.begin(0);
        inner.active_operations.clear();
        inner.events.clear();
        inner.state = State::Disconnected;
        inner.shutdown.complete();
        OR_STATUS_OK
    })
}

fn write_operation(out_operation_id: *mut u64, operation: u64) -> i32 {
    if out_operation_id.is_null() {
        return OR_STATUS_INVALID_ARGUMENT;
    }
    // SAFETY: The caller supplied a non-null writable output slot.
    unsafe { *out_operation_id = operation };
    OR_STATUS_OK
}

#[no_mangle]
/// Starts fail-closed connection preparation.
///
/// # Safety
/// `out_operation_id` must be a writable `u64` for this call.
pub unsafe extern "C" fn or_client_connect(handle: u64, out_operation_id: *mut u64) -> i32 {
    ffi_boundary(|| {
        if out_operation_id.is_null() {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        let call = match begin_call(handle) {
            Ok(call) => call,
            Err(status) => return status,
        };
        let operation = {
            let mut inner = lock(&call.client.inner);
            if !matches!(inner.state, State::Disconnected | State::Blocked) {
                return OR_STATUS_INVALID_STATE;
            }
            let operation = inner.next_operation();
            inner.set_state(State::Preparing, operation);
            inner.set_state(State::ApplyingKillSwitch, operation);
            inner.event(
                EVENT_PLATFORM_ACTION,
                operation,
                OR_STATUS_OK,
                ACTION_APPLY_KILL_SWITCH,
                &[],
            );
            operation
        };
        write_operation(out_operation_id, operation)
    })
}

#[no_mangle]
/// Stops the client in deterministic reverse order.
///
/// # Safety
/// `out_operation_id` must be a writable `u64` for this call.
pub unsafe extern "C" fn or_client_disconnect(handle: u64, out_operation_id: *mut u64) -> i32 {
    ffi_boundary(|| {
        if out_operation_id.is_null() {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        let call = match begin_call(handle) {
            Ok(call) => call,
            Err(status) => return status,
        };
        let operation = {
            let mut inner = lock(&call.client.inner);
            if inner.state == State::Disconnected {
                return OR_STATUS_INVALID_STATE;
            }
            let operation = inner.next_operation();
            inner.set_state(State::Disconnecting, operation);
            inner.event(
                EVENT_PLATFORM_ACTION,
                operation,
                OR_STATUS_OK,
                ACTION_STOP_PROTECTED_CORE,
                &[],
            );
            inner.set_state(State::Disconnected, operation);
            inner.finish_operation(operation, OR_STATUS_OK);
            operation
        };
        write_operation(out_operation_id, operation)
    })
}

#[no_mangle]
pub extern "C" fn or_client_set_tunnel_ready(handle: u64, ready: u8) -> i32 {
    ffi_boundary(|| {
        let call = match begin_call(handle) {
            Ok(call) => call,
            Err(status) => return status,
        };
        let mut inner = lock(&call.client.inner);
        if inner.state != State::ApplyingKillSwitch {
            return OR_STATUS_INVALID_STATE;
        }
        let operation = inner.active_operations.iter().copied().min().unwrap_or(0);
        if ready == 1 {
            inner.set_state(State::BootstrappingTor, operation);
            inner.event(
                EVENT_PLATFORM_ACTION,
                operation,
                OR_STATUS_OK,
                ACTION_START_PROTECTED_CORE,
                &[],
            );
            OR_STATUS_OK
        } else if ready == 0 {
            inner.set_state(State::Blocked, operation);
            inner.finish_operation(operation, OR_STATUS_UNAVAILABLE);
            OR_STATUS_UNAVAILABLE
        } else {
            OR_STATUS_INVALID_ARGUMENT
        }
    })
}

#[no_mangle]
pub extern "C" fn or_client_set_core_ready(handle: u64, ready: u8) -> i32 {
    ffi_boundary(|| {
        let call = match begin_call(handle) {
            Ok(call) => call,
            Err(status) => return status,
        };
        let mut inner = lock(&call.client.inner);
        if !matches!(
            inner.state,
            State::BootstrappingTor | State::Rotating | State::Reconnecting
        ) {
            return OR_STATUS_INVALID_STATE;
        }
        if ready > 1 {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        let operation = inner.active_operations.iter().copied().min().unwrap_or(0);
        if ready == 1 {
            inner.set_state(State::Connected, operation);
            inner.finish_operation(operation, OR_STATUS_OK);
            OR_STATUS_OK
        } else {
            inner.set_state(State::Blocked, operation);
            inner.finish_operation(operation, OR_STATUS_UNAVAILABLE);
            OR_STATUS_UNAVAILABLE
        }
    })
}

#[no_mangle]
pub extern "C" fn or_client_set_network(
    handle: u64,
    available: u8,
    expensive: u8,
    constrained: u8,
    captive: u8,
) -> i32 {
    ffi_boundary(|| {
        if [available, expensive, constrained, captive]
            .iter()
            .any(|value| *value > 1)
        {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        let call = match begin_call(handle) {
            Ok(call) => call,
            Err(status) => return status,
        };
        let mut inner = lock(&call.client.inner);
        let flags = (expensive as u64) | ((constrained as u64) << 1) | ((captive as u64) << 2);
        if available == 0 {
            inner.event(
                EVENT_DIAGNOSTIC,
                0,
                DIAGNOSTIC_NETWORK_UNAVAILABLE,
                flags,
                &[],
            );
            if matches!(
                inner.state,
                State::Connected | State::Rotating | State::BootstrappingTor
            ) {
                inner.set_state(State::Reconnecting, 0);
            }
            return OR_STATUS_OK;
        }
        if captive == 1 {
            inner.event(EVENT_DIAGNOSTIC, 0, DIAGNOSTIC_CAPTIVE_PORTAL, flags, &[]);
            if inner.state != State::Disconnected {
                // User packets remain blocked, but a validated replacement path
                // can recover automatically without removing the TUN.
                inner.set_state(State::Reconnecting, 0);
            }
            return OR_STATUS_OK;
        }
        if inner.state == State::Reconnecting {
            inner.set_state(State::BootstrappingTor, 0);
            inner.event(
                EVENT_PLATFORM_ACTION,
                0,
                OR_STATUS_OK,
                ACTION_START_PROTECTED_CORE,
                &[],
            );
        }
        OR_STATUS_OK
    })
}

#[no_mangle]
/// Sets the two-byte uppercase exit-country selector.
///
/// # Safety
/// `country` must point to at least two readable bytes for this call.
pub unsafe extern "C" fn or_client_set_country(handle: u64, country: *const u8) -> i32 {
    ffi_boundary(|| {
        if country.is_null() {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: The C API requires an addressable two-byte country array.
        let bytes = unsafe { slice::from_raw_parts(country, 2) };
        if !bytes.iter().all(|byte| byte.is_ascii_uppercase()) {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        let call = match begin_call(handle) {
            Ok(call) => call,
            Err(status) => return status,
        };
        lock(&call.client.inner).country = Some([bytes[0], bytes[1]]);
        OR_STATUS_OK
    })
}

#[no_mangle]
pub extern "C" fn or_client_set_anonymity_mode(handle: u64, mode: u32) -> i32 {
    ffi_boundary(|| {
        if mode > 3 {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        let call = match begin_call(handle) {
            Ok(call) => call,
            Err(status) => return status,
        };
        lock(&call.client.inner).anonymity_mode = mode;
        OR_STATUS_OK
    })
}

#[no_mangle]
/// Requests a soft or hard protected-route rotation.
///
/// # Safety
/// `out_operation_id` must be a writable `u64` for this call.
pub unsafe extern "C" fn or_client_rotate(
    handle: u64,
    kind: u32,
    out_operation_id: *mut u64,
) -> i32 {
    ffi_boundary(|| {
        if kind > 1 || out_operation_id.is_null() {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        let call = match begin_call(handle) {
            Ok(call) => call,
            Err(status) => return status,
        };
        let operation = {
            let mut inner = lock(&call.client.inner);
            if inner.state != State::Connected {
                return OR_STATUS_INVALID_STATE;
            }
            let operation = inner.next_operation();
            inner.set_state(State::Rotating, operation);
            inner.event(
                EVENT_PLATFORM_ACTION,
                operation,
                OR_STATUS_OK,
                ACTION_START_PROTECTED_CORE,
                &[kind as u8],
            );
            operation
        };
        write_operation(out_operation_id, operation)
    })
}

fn request_action(handle: u64, action: u64, out_operation_id: *mut u64) -> i32 {
    if out_operation_id.is_null() {
        return OR_STATUS_INVALID_ARGUMENT;
    }
    let call = match begin_call(handle) {
        Ok(call) => call,
        Err(status) => return status,
    };
    let operation = {
        let mut inner = lock(&call.client.inner);
        let operation = inner.next_operation();
        inner.event(EVENT_PLATFORM_ACTION, operation, OR_STATUS_OK, action, &[]);
        operation
    };
    write_operation(out_operation_id, operation)
}

#[no_mangle]
/// Requests anonymous capability-token refresh.
///
/// # Safety
/// `out_operation_id` must be a writable `u64` for this call.
pub unsafe extern "C" fn or_client_request_token_refresh(
    handle: u64,
    out_operation_id: *mut u64,
) -> i32 {
    ffi_boundary(|| request_action(handle, ACTION_REFRESH_TOKEN, out_operation_id))
}

#[no_mangle]
/// Requests refresh of signed configuration/catalog data.
///
/// # Safety
/// `out_operation_id` must be a writable `u64` for this call.
pub unsafe extern "C" fn or_client_request_config_refresh(
    handle: u64,
    out_operation_id: *mut u64,
) -> i32 {
    ffi_boundary(|| request_action(handle, ACTION_REFRESH_SIGNED_CONFIG, out_operation_id))
}

#[no_mangle]
pub extern "C" fn or_client_cancel(handle: u64, operation_id: u64) -> i32 {
    ffi_boundary(|| {
        if operation_id == 0 {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        let call = match begin_call(handle) {
            Ok(call) => call,
            Err(status) => return status,
        };
        let mut inner = lock(&call.client.inner);
        if !inner.active_operations.remove(&operation_id) {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        inner.event(EVENT_OPERATION, operation_id, OR_STATUS_CANCELLED, 0, &[]);
        OR_STATUS_OK
    })
}

#[no_mangle]
pub extern "C" fn or_client_suspend(handle: u64, monotonic_ms: u64) -> i32 {
    ffi_boundary(|| {
        let call = match begin_call(handle) {
            Ok(call) => call,
            Err(status) => return status,
        };
        let mut inner = lock(&call.client.inner);
        inner.suspended_at_ms = Some(monotonic_ms);
        OR_STATUS_OK
    })
}

#[no_mangle]
pub extern "C" fn or_client_resume(
    handle: u64,
    monotonic_ms: u64,
    protected_path_healthy: u8,
) -> i32 {
    ffi_boundary(|| {
        if protected_path_healthy > 1 {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        let call = match begin_call(handle) {
            Ok(call) => call,
            Err(status) => return status,
        };
        let mut inner = lock(&call.client.inner);
        let suspended_at = match inner.suspended_at_ms.take() {
            Some(value) => value,
            None => return OR_STATUS_INVALID_STATE,
        };
        if monotonic_ms < suspended_at {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        if protected_path_healthy == 0 && inner.state != State::Disconnected {
            inner.event(
                EVENT_DIAGNOSTIC,
                0,
                DIAGNOSTIC_PROTECTED_PATH_UNHEALTHY,
                monotonic_ms - suspended_at,
                &[],
            );
            inner.set_state(State::Reconnecting, 0);
        }
        OR_STATUS_OK
    })
}

#[no_mangle]
/// Submits one complete bounded IP packet.
///
/// # Safety
/// `packet` must describe `packet_len` readable bytes for this call.
pub unsafe extern "C" fn or_client_submit_packet(
    handle: u64,
    packet: *const u8,
    packet_len: usize,
) -> i32 {
    ffi_boundary(|| {
        if packet.is_null() || packet_len == 0 || packet_len > MAX_PACKET_BYTES {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: The caller promises a readable buffer for this call. The slice
        // is not stored and no Rust reference crosses the boundary.
        let _packet = unsafe { slice::from_raw_parts(packet, packet_len) };
        let call = match begin_call(handle) {
            Ok(call) => call,
            Err(status) => return status,
        };
        let mut inner = lock(&call.client.inner);
        if !inner.packet_unavailable_reported {
            inner.packet_unavailable_reported = true;
            inner.event(
                EVENT_DIAGNOSTIC,
                0,
                DIAGNOSTIC_PACKET_CORE_UNAVAILABLE,
                0,
                &[],
            );
        }
        OR_STATUS_UNAVAILABLE
    })
}

#[no_mangle]
/// Copies the next queued event into caller-owned storage.
///
/// # Safety
/// `out_event` must be a writable, aligned `OrEvent` for this call.
pub unsafe extern "C" fn or_client_poll_event(handle: u64, out_event: *mut OrEvent) -> i32 {
    ffi_boundary(|| {
        if out_event.is_null() {
            return OR_STATUS_INVALID_ARGUMENT;
        }
        let call = match begin_call(handle) {
            Ok(call) => call,
            Err(status) => return status,
        };
        let event = match lock(&call.client.inner).events.pop_front() {
            Some(event) => event,
            None => return OR_STATUS_EMPTY,
        };
        // SAFETY: Validated non-null; the caller owns this output slot.
        unsafe { *out_event = event };
        OR_STATUS_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    fn options(capacity: u32) -> OrCreateOptions {
        OrCreateOptions {
            struct_size: std::mem::size_of::<OrCreateOptions>() as u32,
            abi_min_major: 1,
            abi_min_minor: 0,
            abi_max_major: 1,
            abi_max_minor: 0,
            event_capacity: capacity,
            memory_budget_bytes: MIN_MEMORY_BUDGET,
        }
    }

    fn create(capacity: u32) -> u64 {
        let mut handle = 0;
        assert_eq!(
            unsafe { or_client_create(&options(capacity), &mut handle) },
            OR_STATUS_OK
        );
        assert_ne!(handle, 0);
        handle
    }

    #[test]
    fn version_negotiation_rejects_other_major() {
        let mut incompatible = options(8);
        incompatible.abi_min_major = 2;
        incompatible.abi_max_major = 2;
        let mut handle = 0;
        assert_eq!(
            unsafe { or_client_create(&incompatible, &mut handle) },
            OR_STATUS_INCOMPATIBLE_VERSION
        );
        assert_eq!(handle, 0);
    }

    #[test]
    fn abi_struct_layout_matches_c_header_v1() {
        assert_eq!(std::mem::size_of::<OrCreateOptions>(), 24);
        assert_eq!(std::mem::align_of::<OrCreateOptions>(), 8);
        assert_eq!(std::mem::size_of::<OrEvent>(), 104);
        assert_eq!(std::mem::align_of::<OrEvent>(), 8);
    }

    #[test]
    fn null_pointer_arguments_are_rejected() {
        let mut handle = 0;
        assert_eq!(
            unsafe { or_client_create(std::ptr::null(), &mut handle) },
            OR_STATUS_INVALID_ARGUMENT
        );
        let handle = create(8);
        assert_eq!(
            unsafe { or_client_set_country(handle, std::ptr::null()) },
            OR_STATUS_INVALID_ARGUMENT
        );
        assert_eq!(
            unsafe { or_client_submit_packet(handle, std::ptr::null(), 20) },
            OR_STATUS_INVALID_ARGUMENT
        );
        assert_eq!(
            unsafe { or_client_poll_event(handle, std::ptr::null_mut()) },
            OR_STATUS_INVALID_ARGUMENT
        );
        assert_eq!(or_client_destroy(handle), OR_STATUS_OK);
    }

    #[test]
    fn panic_boundary_returns_stable_status() {
        assert_eq!(ffi_boundary(|| panic!("test panic")), OR_STATUS_PANIC);
    }

    #[test]
    fn handle_is_invalid_immediately_after_destroy() {
        let handle = create(8);
        assert_eq!(or_client_destroy(handle), OR_STATUS_OK);
        let mut event = OrEvent::default();
        assert_eq!(
            unsafe { or_client_poll_event(handle, &mut event) },
            OR_STATUS_INVALID_HANDLE
        );
        assert_eq!(or_client_destroy(handle), OR_STATUS_INVALID_HANDLE);
    }

    #[test]
    fn connect_waits_for_platform_then_core() {
        let handle = create(16);
        let mut operation = 0;
        assert_eq!(
            unsafe { or_client_connect(handle, &mut operation) },
            OR_STATUS_OK
        );
        assert_ne!(operation, 0);
        assert_eq!(or_client_set_tunnel_ready(handle, 1), OR_STATUS_OK);
        assert_eq!(or_client_set_core_ready(handle, 1), OR_STATUS_OK);

        let mut states = Vec::new();
        loop {
            let mut event = OrEvent::default();
            if unsafe { or_client_poll_event(handle, &mut event) } == OR_STATUS_EMPTY {
                break;
            }
            if event.kind == EVENT_STATE_CHANGED {
                states.push(event.value);
            }
        }
        assert_eq!(
            states,
            vec![
                State::Preparing as u64,
                State::ApplyingKillSwitch as u64,
                State::BootstrappingTor as u64,
                State::Connected as u64
            ]
        );
        assert_eq!(or_client_destroy(handle), OR_STATUS_OK);
    }

    #[test]
    fn packet_path_is_bounded_and_fails_closed_until_adapter_exists() {
        let handle = create(8);
        let packet = [0x45u8; 20];
        assert_eq!(
            unsafe { or_client_submit_packet(handle, packet.as_ptr(), packet.len()) },
            OR_STATUS_UNAVAILABLE
        );
        assert_eq!(
            unsafe { or_client_submit_packet(handle, packet.as_ptr(), MAX_PACKET_BYTES + 1) },
            OR_STATUS_INVALID_ARGUMENT
        );
        assert_eq!(or_client_destroy(handle), OR_STATUS_OK);
    }

    #[test]
    fn event_queue_stays_bounded_and_reports_overflow() {
        let handle = create(8);
        for _ in 0..32 {
            let mut operation = 0;
            assert_eq!(
                unsafe { or_client_request_token_refresh(handle, &mut operation) },
                OR_STATUS_OK
            );
        }
        let mut count = 0;
        let mut overflow = false;
        loop {
            let mut event = OrEvent::default();
            if unsafe { or_client_poll_event(handle, &mut event) } == OR_STATUS_EMPTY {
                break;
            }
            count += 1;
            overflow |= event.kind == EVENT_QUEUE_OVERFLOW;
        }
        assert!(count <= 8);
        assert!(overflow);
        assert_eq!(or_client_destroy(handle), OR_STATUS_OK);
    }

    #[test]
    fn cancellation_is_explicit() {
        let handle = create(8);
        let mut operation = 0;
        assert_eq!(
            unsafe { or_client_request_config_refresh(handle, &mut operation) },
            OR_STATUS_OK
        );
        assert_eq!(or_client_cancel(handle, operation), OR_STATUS_OK);
        assert_eq!(
            or_client_cancel(handle, operation),
            OR_STATUS_INVALID_ARGUMENT
        );
        assert_eq!(or_client_destroy(handle), OR_STATUS_OK);
    }

    #[test]
    fn destroy_and_calls_are_thread_safe() {
        let handle = create(32);
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let worker = thread::spawn(move || {
            worker_barrier.wait();
            for _ in 0..100 {
                let _ = or_client_set_network(handle, 1, 0, 0, 0);
            }
        });
        barrier.wait();
        assert_eq!(or_client_destroy(handle), OR_STATUS_OK);
        worker.join().expect("worker must not panic");
        assert_eq!(
            or_client_set_network(handle, 1, 0, 0, 0),
            OR_STATUS_INVALID_HANDLE
        );
    }

    #[test]
    fn handoff_never_returns_to_connected_without_new_health_proof() {
        let handle = create(32);
        let mut operation = 0;
        assert_eq!(
            unsafe { or_client_connect(handle, &mut operation) },
            OR_STATUS_OK
        );
        assert_eq!(or_client_set_tunnel_ready(handle, 1), OR_STATUS_OK);
        assert_eq!(or_client_set_core_ready(handle, 1), OR_STATUS_OK);
        assert_eq!(or_client_set_network(handle, 0, 0, 0, 0), OR_STATUS_OK);
        assert_eq!(or_client_set_network(handle, 1, 1, 0, 0), OR_STATUS_OK);

        let mut states = Vec::new();
        loop {
            let mut event = OrEvent::default();
            if unsafe { or_client_poll_event(handle, &mut event) } == OR_STATUS_EMPTY {
                break;
            }
            if event.kind == EVENT_STATE_CHANGED {
                states.push(event.value);
            }
        }
        assert!(states.ends_with(&[
            State::Connected as u64,
            State::Reconnecting as u64,
            State::BootstrappingTor as u64,
        ]));
        assert_eq!(or_client_destroy(handle), OR_STATUS_OK);
    }

    #[test]
    fn unhealthy_resume_forces_reconnect() {
        let handle = create(16);
        let mut operation = 0;
        assert_eq!(
            unsafe { or_client_connect(handle, &mut operation) },
            OR_STATUS_OK
        );
        assert_eq!(or_client_set_tunnel_ready(handle, 1), OR_STATUS_OK);
        assert_eq!(or_client_set_core_ready(handle, 1), OR_STATUS_OK);
        assert_eq!(or_client_suspend(handle, 1_000), OR_STATUS_OK);
        assert_eq!(or_client_resume(handle, 5_000, 0), OR_STATUS_OK);

        let mut last_state = None;
        loop {
            let mut event = OrEvent::default();
            if unsafe { or_client_poll_event(handle, &mut event) } == OR_STATUS_EMPTY {
                break;
            }
            if event.kind == EVENT_STATE_CHANGED {
                last_state = Some(event.value);
            }
        }
        assert_eq!(last_state, Some(State::Reconnecting as u64));
        assert_eq!(or_client_destroy(handle), OR_STATUS_OK);
    }
}
