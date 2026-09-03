// file: agent/ebpf/src/user_daemon.rs
//! Threat Analyser eBPF User-Space Daemon
//!
//! Loads eBPF bytecode into Linux kernel, polls the shared memory ring buffer,
//! converts raw kernel syscall structs into OCSF v1.1.0 telemetry, and ships
//! batches to Threat Analyser backend API via HTTPS.

use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct OCSFProcessActivity {
    pub class_uid: u32,       // 1007 = Process Activity
    pub category_uid: u32,    // 1 = System Activity
    pub activity_id: u32,     // 1 = Launch / Execve
    pub time: u64,
    pub metadata: OCSFMetadata,
    pub process: OCSFProcess,
    pub actor: OCSFActor,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OCSFNetworkActivity {
    pub class_uid: u32,       // 4001 = Network Activity
    pub category_uid: u32,    // 4 = Network Activity
    pub activity_id: u32,     // 1 = Connect
    pub time: u64,
    pub metadata: OCSFMetadata,
    pub dst_endpoint: OCSFEndpoint,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OCSFMetadata {
    pub version: String,
    pub product: OCSFProduct,
    pub source_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OCSFProduct {
    pub name: String,
    pub vendor_name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OCSFProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmd_line: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OCSFActor {
    pub user: OCSFUser,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OCSFUser {
    pub uid: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OCSFEndpoint {
    pub ip: String,
    pub port: u16,
}

pub fn convert_execve_to_ocsf(pid: u32, uid: u32, comm: &str) -> OCSFProcessActivity {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    OCSFProcessActivity {
        class_uid: 1007,
        category_uid: 1,
        activity_id: 1,
        time: now,
        metadata: OCSFMetadata {
            version: "1.1.0".to_string(),
            product: OCSFProduct {
                name: "Threat Analyser eBPF Engine".to_string(),
                vendor_name: "Threat Analyser".to_string(),
                version: "4.0.0".to_string(),
            },
            source_type: "ebpf_kernel_tracepoint".to_string(),
        },
        process: OCSFProcess {
            pid,
            ppid: 1,
            name: comm.to_string(),
            cmd_line: comm.to_string(),
        },
        actor: OCSFActor {
            user: OCSFUser {
                uid: uid.to_string(),
                name: if uid == 0 { "root".to_string() } else { format!("user-{}", uid) },
            },
        },
    }
}

pub fn convert_connect_to_ocsf(pid: u32, ip: &str, port: u16) -> OCSFNetworkActivity {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    OCSFNetworkActivity {
        class_uid: 4001,
        category_uid: 4,
        activity_id: 1,
        time: now,
        metadata: OCSFMetadata {
            version: "1.1.0".to_string(),
            product: OCSFProduct {
                name: "Threat Analyser eBPF Engine".to_string(),
                vendor_name: "Threat Analyser".to_string(),
                version: "4.0.0".to_string(),
            },
            source_type: "ebpf_kernel_socket".to_string(),
        },
        dst_endpoint: OCSFEndpoint {
            ip: ip.to_string(),
            port,
        },
    }
}
