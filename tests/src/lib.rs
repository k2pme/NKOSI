#[cfg(test)]
mod integration {
    pub mod agent_test;
    pub mod api_test;
    pub mod db_test;
    pub mod engine_fuzz_test;
    pub mod firewall_test;
    pub mod health_test;
    pub mod monitor_test;
    pub mod quarantine_test;
    pub mod risk_test;
    pub mod scan_integration_test;
    pub mod scan_test;
    pub mod ti_integrity_test;
}

#[cfg(test)]
mod tests {
    use super::integration::*;

    #[test]
    fn test_scan_malicious() {
        scan_test::test_scan_malicious_file();
    }

    #[test]
    fn test_scan_clean() {
        scan_test::test_scan_clean_file();
    }

    #[test]
    fn test_risk_clean() {
        risk_test::test_risk_clean();
    }

    #[test]
    fn test_risk_malicious() {
        risk_test::test_risk_malicious();
    }

    #[test]
    fn test_db_crud() {
        db_test::test_db_insert_event();
    }

    #[test]
    fn test_health_tracker() {
        health_test::test_health_all_ok();
    }

    // Agent multi-agent tests
    #[test]
    fn test_agent_upsert_and_get_all() {
        agent_test::agent_upsert_and_get_all();
    }

    #[test]
    fn test_agent_upsert_idempotent() {
        agent_test::agent_upsert_idempotent();
    }

    #[test]
    fn test_agent_get_by_id() {
        agent_test::agent_get_by_id();
    }

    #[test]
    fn test_agent_get_by_id_not_found() {
        agent_test::agent_get_by_id_not_found();
    }

    #[test]
    fn test_agent_heartbeat() {
        agent_test::agent_heartbeat();
    }

    #[test]
    fn test_agent_mark_offline_stale() {
        agent_test::agent_mark_offline_stale();
    }

    #[test]
    fn test_events_with_agent_filter() {
        agent_test::events_with_agent_filter();
    }

    #[test]
    fn test_consolidated_stats() {
        agent_test::consolidated_stats();
    }

    #[test]
    fn test_full_lifecycle() {
        agent_test::full_lifecycle();
    }

    // Scan integration tests
    #[test]
    fn test_scan_and_store_results() {
        scan_integration_test::scan_and_store_results();
    }

    #[test]
    fn test_scan_risk_assessment_pipeline() {
        scan_integration_test::scan_risk_assessment_pipeline();
    }

    #[test]
    fn test_scan_and_persist_full_flow() {
        scan_integration_test::scan_and_persist_full_flow();
    }

    // Monitor tests
    #[test]
    fn test_monitor_event_type_exhaustive() {
        monitor_test::test_event_type_variants_exhaustive();
    }

    #[test]
    fn test_event_bus_send_receive() {
        monitor_test::test_event_bus_send_receive();
    }

    // Engine fuzz tests
    #[test]
    fn test_yara_fuzz_random_bytes() {
        engine_fuzz_test::test_yara_fuzz_random_bytes();
    }

    #[test]
    fn test_hash_fuzz_edge_cases() {
        engine_fuzz_test::test_hash_fuzz_edge_cases();
    }

    #[test]
    fn test_static_analyzer_fuzz() {
        engine_fuzz_test::test_static_analyzer_fuzz();
    }

    // API tests
    #[test]
    fn test_agent_serialization_roundtrip() {
        api_test::test_agent_serialization_roundtrip();
    }

    #[test]
    fn test_severity_serialization() {
        api_test::test_severity_serialization();
    }
}
