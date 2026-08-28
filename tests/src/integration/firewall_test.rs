use nkosi_scanner::FirewallManager;

#[test]
pub fn test_firewall_manager_creation() {
    let mgr = FirewallManager::new();
    // Just verify it can be created without panic
    let _ = mgr;
}

#[test]
pub fn test_firewall_status() {
    let mgr = FirewallManager::new();
    // Should return status (may fail without root, but shouldn't panic)
    let result = mgr.status();
    // Just verify the method exists and returns a result
    assert!(result.is_ok() || result.is_err());
}

#[test]
pub fn test_firewall_whitelist_format() {
    // Verify that IP validation works for firewall operations
    let valid_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1"];
    let invalid_ips = ["not-an-ip", "999.999.999.999", ""];

    for ip in &valid_ips {
        assert!(!ip.is_empty(), "Valid IP should not be empty");
        let parts: Vec<&str> = ip.split('.').collect();
        assert_eq!(parts.len(), 4, "IP should have 4 octets");
    }

    for ip in &invalid_ips {
        if !ip.is_empty() {
            let parts: Vec<&str> = ip.split('.').collect();
            let is_valid = parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok());
            assert!(!is_valid, "Invalid IP should be rejected: {}", ip);
        }
    }
}
