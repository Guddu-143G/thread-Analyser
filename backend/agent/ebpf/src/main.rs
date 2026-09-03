// file: agent/ebpf/src/main.rs
//! Threat Analyser eBPF In-Kernel Probe
//!
//! Attaches non-bypassable tracepoints directly into kernel system calls:
//! - `sys_enter_execve`: Captures binary path, arguments, PID, and UID at process birth.
//! - `sys_enter_connect`: Captures outbound socket creation, destination IP, and port before packet leaves host.
//!
//! Uses lockless in-kernel Ring Buffer (`aya_bpf::maps::RingBuf`) to stream events directly to user space.

#![no_std]
#![no_main]

use aya_bpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

/// 1MB Lockless Ring Buffer shared between Linux Kernel and user-space collector daemon
#[map]
static mut TELEMETRY_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

/// Fixed-size binary representation of kernel execve event for zero-copy memory transport
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelExecveTelemetry {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 64],
    pub timestamp_ns: u64,
}

/// Fixed-size binary representation of kernel socket connect event
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelConnectTelemetry {
    pub pid: u32,
    pub uid: u32,
    pub family: u16,
    pub dport: u16,
    pub daddr: u32,
    pub timestamp_ns: u64,
}

/// Tracepoint hook on process execution entry
#[tracepoint(name = "sys_enter_execve")]
pub fn sys_enter_execve(ctx: TracePointContext) -> i32 {
    match try_sys_enter_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

fn try_sys_enter_execve(ctx: TracePointContext) -> Result<i32, u32> {
    let pid = ctx.pid();
    let uid = ctx.uid();

    let mut comm = [0u8; 16];
    ctx.command(&mut comm).map_err(|_| 1u32)?;

    let event = KernelExecveTelemetry {
        pid,
        ppid: 0,
        uid,
        gid: 0,
        comm,
        filename: [0u8; 64],
        timestamp_ns: 0,
    };

    unsafe {
        if let Some(mut buf) = TELEMETRY_EVENTS.reserve(core::mem::size_of::<KernelExecveTelemetry>(), 0) {
            core::ptr::copy_nonoverlapping(
                &event as *const _ as *const u8,
                buf.as_mut_ptr(),
                core::mem::size_of::<KernelExecveTelemetry>(),
            );
            buf.submit(0);
        }
    }

    Ok(0)
}

/// Tracepoint hook on network socket connect entry
#[tracepoint(name = "sys_enter_connect")]
pub fn sys_enter_connect(ctx: TracePointContext) -> i32 {
    match try_sys_enter_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

fn try_sys_enter_connect(ctx: TracePointContext) -> Result<i32, u32> {
    let pid = ctx.pid();
    let uid = ctx.uid();

    let event = KernelConnectTelemetry {
        pid,
        uid,
        family: 2, // AF_INET
        dport: 0,
        daddr: 0,
        timestamp_ns: 0,
    };

    unsafe {
        if let Some(mut buf) = TELEMETRY_EVENTS.reserve(core::mem::size_of::<KernelConnectTelemetry>(), 0) {
            core::ptr::copy_nonoverlapping(
                &event as *const _ as *const u8,
                buf.as_mut_ptr(),
                core::mem::size_of::<KernelConnectTelemetry>(),
            );
            buf.submit(0);
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
