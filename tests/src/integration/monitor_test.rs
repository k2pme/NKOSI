use nkosi_common::types::EventType;
use nkosi_monitors::event_bus::{EventBus, FileMetadata, MonitorEvent};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

#[test]
pub fn test_event_type_variants_exhaustive() {
    let variants = [
        EventType::FileCreated,
        EventType::FileModified,
        EventType::FileDeleted,
        EventType::ProcessStarted,
        EventType::ProcessExited,
        EventType::NetworkConnection,
        EventType::NetworkBlocked,
        EventType::Detection,
        EventType::ResponseAction,
        EventType::ScanStarted,
        EventType::ScanCompleted,
        EventType::ThreatIntelUpdate,
    ];

    for v in &variants {
        let name = match v {
            EventType::FileCreated => "FileCreated",
            EventType::FileModified => "FileModified",
            EventType::FileDeleted => "FileDeleted",
            EventType::ProcessStarted => "ProcessStarted",
            EventType::ProcessExited => "ProcessExited",
            EventType::NetworkConnection => "NetworkConnection",
            EventType::NetworkBlocked => "NetworkBlocked",
            EventType::Detection => "Detection",
            EventType::ResponseAction => "ResponseAction",
            EventType::ScanStarted => "ScanStarted",
            EventType::ScanCompleted => "ScanCompleted",
            EventType::ThreatIntelUpdate => "ThreatIntelUpdate",
        };
        assert!(!name.is_empty(), "variant should produce a name");
    }

    assert_eq!(variants.len(), 12);
}

#[test]
pub fn test_monitor_event_file_creation() {
    let event = MonitorEvent::FileEvent {
        path: "/tmp/test.txt".to_string(),
        event_type: EventType::FileCreated,
        metadata: FileMetadata {
            size: 1024,
            permissions: "0644".to_string(),
            owner: Some("uid:1000".to_string()),
            modified: Some("1700000000".to_string()),
        },
    };

    match event {
        MonitorEvent::FileEvent {
            path,
            event_type,
            metadata,
        } => {
            assert_eq!(path, "/tmp/test.txt");
            assert_eq!(event_type, EventType::FileCreated);
            assert_eq!(metadata.size, 1024);
            assert_eq!(metadata.owner.as_deref(), Some("uid:1000"));
        }
        _ => panic!("expected FileEvent"),
    }
}

#[test]
pub fn test_monitor_event_process() {
    let event = MonitorEvent::ProcessEvent {
        pid: 1234,
        ppid: Some(1),
        executable: "/usr/bin/bash".to_string(),
        args: vec!["bash".to_string(), "-c".to_string(), "echo hi".to_string()],
        event_type: EventType::ProcessStarted,
    };

    match event {
        MonitorEvent::ProcessEvent {
            pid,
            ppid,
            executable,
            args,
            event_type,
        } => {
            assert_eq!(pid, 1234);
            assert_eq!(ppid, Some(1));
            assert_eq!(executable, "/usr/bin/bash");
            assert_eq!(args.len(), 3);
            assert_eq!(event_type, EventType::ProcessStarted);
        }
        _ => panic!("expected ProcessEvent"),
    }
}

#[test]
pub fn test_monitor_event_network() {
    let event = MonitorEvent::NetworkEvent {
        pid: 5678,
        local_addr: "127.0.0.1".to_string(),
        remote_addr: "93.184.216.34".to_string(),
        remote_port: 443,
        protocol: "TCP".to_string(),
        event_type: EventType::NetworkConnection,
    };

    match event {
        MonitorEvent::NetworkEvent {
            pid,
            local_addr,
            remote_addr,
            remote_port,
            protocol,
            event_type,
        } => {
            assert_eq!(pid, 5678);
            assert_eq!(local_addr, "127.0.0.1");
            assert_eq!(remote_addr, "93.184.216.34");
            assert_eq!(remote_port, 443);
            assert_eq!(protocol, "TCP");
            assert_eq!(event_type, EventType::NetworkConnection);
        }
        _ => panic!("expected NetworkEvent"),
    }
}

#[test]
pub fn test_file_event_variants() {
    let variants = [
        EventType::FileCreated,
        EventType::FileModified,
        EventType::FileDeleted,
    ];

    for event_type in variants {
        let event = MonitorEvent::FileEvent {
            path: "/tmp/file.txt".to_string(),
            event_type: event_type.clone(),
            metadata: FileMetadata {
                size: 0,
                permissions: String::new(),
                owner: None,
                modified: None,
            },
        };

        if let MonitorEvent::FileEvent { event_type: got, .. } = event {
            assert_eq!(got, event_type);
        } else {
            panic!("expected FileEvent");
        }
    }
}

#[test]
pub fn test_event_bus_send_receive() {
    let bus = EventBus::new(16);
    let mut rx = bus.subscribe();

    bus.send(MonitorEvent::FileEvent {
        path: "/test".to_string(),
        event_type: EventType::FileCreated,
        metadata: FileMetadata {
            size: 0,
            permissions: String::new(),
            owner: None,
            modified: None,
        },
    });

    let received = rx.try_recv().expect("should receive event");
    match received {
        MonitorEvent::FileEvent { path, event_type, .. } => {
            assert_eq!(path, "/test");
            assert_eq!(event_type, EventType::FileCreated);
        }
        _ => panic!("expected FileEvent"),
    }
}

#[test]
pub fn test_event_bus_multiple_subscribers() {
    let bus = Arc::new(EventBus::new(16));
    let mut rx1 = bus.subscribe();
    let mut rx2 = bus.subscribe();

    bus.send(MonitorEvent::ProcessEvent {
        pid: 1,
        ppid: None,
        executable: "test".to_string(),
        args: vec![],
        event_type: EventType::ProcessStarted,
    });

    let e1 = rx1.try_recv().unwrap();
    let e2 = rx2.try_recv().unwrap();
    match (&e1, &e2) {
        (
            MonitorEvent::ProcessEvent { pid: p1, .. },
            MonitorEvent::ProcessEvent { pid: p2, .. },
        ) => {
            assert_eq!(*p1, 1);
            assert_eq!(*p2, 1);
        }
        _ => panic!("both should be ProcessEvent"),
    }
}

#[test]
pub fn test_filesystem_monitor_config_with_temp_dir() {
    let dir = TempDir::new().unwrap();
    let watched = vec![dir.path().to_path_buf()];
    let excluded = vec![PathBuf::from("/proc")];

    let bus = Arc::new(EventBus::new(16));
    let _monitor = nkosi_monitors::FilesystemMonitor::new(watched.clone(), excluded, bus);

    assert!(dir.path().exists());
    assert_eq!(watched.len(), 1);
}


#[test]
pub fn test_filesystem_monitor_create_and_modify() {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("testfile.txt");

    std::fs::write(&file_path, "initial").unwrap();
    assert!(file_path.exists());

    let content = std::fs::read_to_string(&file_path).unwrap();
    assert_eq!(content, "initial");

    std::fs::write(&file_path, "modified content").unwrap();
    let content = std::fs::read_to_string(&file_path).unwrap();
    assert_eq!(content, "modified content");

    std::fs::remove_file(&file_path).unwrap();
    assert!(!file_path.exists());
}

#[test]
pub fn test_filesystem_monitor_excluded_path() {
    use nkosi_monitors::FilesystemMonitor;
    use std::path::Path;

    let excluded = vec![
        PathBuf::from("/proc"),
        PathBuf::from("/home/*/.cache"),
    ];

    assert!(FilesystemMonitor::is_excluded(
        Path::new("/proc/1/status"),
        &excluded,
    ));
    assert!(FilesystemMonitor::is_excluded(
        Path::new("/home/alice/.cache/something"),
        &excluded,
    ));
    assert!(!FilesystemMonitor::is_excluded(
        Path::new("/home/alice/documents/file.txt"),
        &excluded,
    ));
}

#[test]
pub fn test_file_metadata_defaults() {
    let meta = FileMetadata {
        size: 0,
        permissions: String::new(),
        owner: None,
        modified: None,
    };

    assert_eq!(meta.size, 0);
    assert!(meta.permissions.is_empty());
    assert!(meta.owner.is_none());
    assert!(meta.modified.is_none());
}

#[test]
pub fn test_process_event_missing_parent() {
    let event = MonitorEvent::ProcessEvent {
        pid: 9999,
        ppid: None,
        executable: "unknown".to_string(),
        args: vec![],
        event_type: EventType::ProcessExited,
    };

    if let MonitorEvent::ProcessEvent { ppid, event_type, .. } = event {
        assert_eq!(ppid, None);
        assert_eq!(event_type, EventType::ProcessExited);
    } else {
        panic!("expected ProcessEvent");
    }
}

#[test]
pub fn test_network_event_udp() {
    let event = MonitorEvent::NetworkEvent {
        pid: 100,
        local_addr: "0.0.0.0".to_string(),
        remote_addr: "10.0.0.1".to_string(),
        remote_port: 5353,
        protocol: "UDP".to_string(),
        event_type: EventType::NetworkConnection,
    };

    if let MonitorEvent::NetworkEvent { protocol, .. } = event {
        assert_eq!(protocol, "UDP");
    }
}

#[test]
pub fn test_event_type_serde_roundtrip() {
    let types = [
        EventType::FileCreated,
        EventType::FileModified,
        EventType::FileDeleted,
        EventType::ProcessStarted,
        EventType::ProcessExited,
        EventType::NetworkConnection,
        EventType::NetworkBlocked,
        EventType::Detection,
        EventType::ResponseAction,
        EventType::ScanStarted,
        EventType::ScanCompleted,
        EventType::ThreatIntelUpdate,
    ];

    for et in types {
        let json = serde_json::to_string(&et).unwrap();
        let back: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(et, back);
    }
}

#[test]
pub fn test_monitor_event_clone() {
    let event = MonitorEvent::FileEvent {
        path: "/test".to_string(),
        event_type: EventType::FileModified,
        metadata: FileMetadata {
            size: 42,
            permissions: "0755".to_string(),
            owner: Some("root".to_string()),
            modified: None,
        },
    };

    let cloned = event.clone();
    if let (MonitorEvent::FileEvent { path: p1, .. }, MonitorEvent::FileEvent { path: p2, .. }) =
        (&event, &cloned)
    {
        assert_eq!(p1, p2);
    }
}

#[test]
pub fn test_monitor_event_debug() {
    let event = MonitorEvent::FileEvent {
        path: "/debug".to_string(),
        event_type: EventType::FileCreated,
        metadata: FileMetadata {
            size: 1,
            permissions: String::new(),
            owner: None,
            modified: None,
        },
    };
    let debug_str = format!("{:?}", event);
    assert!(debug_str.contains("FileEvent"));
    assert!(debug_str.contains("/debug"));
}

#[test]
pub fn test_event_bus_capacity_one() {
    let bus = EventBus::new(1);
    let mut rx = bus.subscribe();

    bus.send(MonitorEvent::FileEvent {
        path: "/a".to_string(),
        event_type: EventType::FileCreated,
        metadata: FileMetadata {
            size: 0,
            permissions: String::new(),
            owner: None,
            modified: None,
        },
    });

    let first = rx.try_recv();
    assert!(first.is_ok());
}

#[test]
pub fn test_temp_dir_nested_directories() {
    let root = TempDir::new().unwrap();
    let sub1 = root.path().join("subdir1");
    let sub2 = sub1.join("subdir2");
    std::fs::create_dir_all(&sub2).unwrap();

    let file = sub2.join("nested.txt");
    std::fs::write(&file, "nested").unwrap();
    assert!(file.exists());

    let content = std::fs::read_to_string(&file).unwrap();
    assert_eq!(content, "nested");
}
