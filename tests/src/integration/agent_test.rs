use chrono::Utc;
use nkosi_common::types::*;
use tempfile::TempDir;

struct TestDb {
    _tmp: TempDir,
    db: nkosi_db::Database,
}

impl TestDb {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("test_agents.db");
        let db = nkosi_db::Database::new(&db_path).unwrap();
        Self { _tmp: tmp, db }
    }
}

pub fn make_agent(id: &str, hostname: &str, status: AgentStatus) -> Agent {
    Agent {
        id: id.to_string(),
        hostname: hostname.to_string(),
        ip_address: "192.168.1.100".to_string(),
        os_version: "Linux 6.1".to_string(),
        nkosi_version: "0.1.0".to_string(),
        agent_name: format!("agent-{}", hostname),
        status,
        last_seen: Utc::now(),
        registered_at: Utc::now(),
        events_count: 0,
        threats_count: 0,
        score: 0,
    }
}

#[test]
pub fn agent_upsert_and_get_all() {
    let test = TestDb::new();
    let repo = nkosi_db::AgentRepository::new(&test.db);

    let a1 = make_agent("a1", "host-alpha", AgentStatus::Online);
    let a2 = make_agent("a2", "host-beta", AgentStatus::Online);

    repo.upsert(&a1).unwrap();
    repo.upsert(&a2).unwrap();

    let all = repo.get_all().unwrap();
    assert_eq!(all.len(), 2, "Should have 2 agents");

    let ids: Vec<&str> = all.iter().map(|a| a.id.as_str()).collect();
    assert!(ids.contains(&"a1"));
    assert!(ids.contains(&"a2"));
}

#[test]
pub fn agent_upsert_idempotent() {
    let test = TestDb::new();
    let repo = nkosi_db::AgentRepository::new(&test.db);

    let mut a1 = make_agent("a1", "host-alpha", AgentStatus::Online);
    repo.upsert(&a1).unwrap();

    a1.score = 85;
    a1.status = AgentStatus::Degraded;
    repo.upsert(&a1).unwrap();

    let all = repo.get_all().unwrap();
    assert_eq!(all.len(), 1, "Upsert should not create duplicates");

    let agent = all.first().unwrap();
    assert_eq!(agent.score, 85);
    assert_eq!(agent.status, AgentStatus::Degraded);
}

#[test]
pub fn agent_get_by_id() {
    let test = TestDb::new();
    let repo = nkosi_db::AgentRepository::new(&test.db);

    let a1 = make_agent("a1", "host-alpha", AgentStatus::Online);
    repo.upsert(&a1).unwrap();

    let found = repo.get_by_id("a1").unwrap();
    assert!(found.is_some(), "Agent should be found by ID");

    let agent = found.unwrap();
    assert_eq!(agent.hostname, "host-alpha");
    assert_eq!(agent.status, AgentStatus::Online);
}

#[test]
pub fn agent_get_by_id_not_found() {
    let test = TestDb::new();
    let repo = nkosi_db::AgentRepository::new(&test.db);

    let found = repo.get_by_id("nonexistent").unwrap();
    assert!(found.is_none(), "Non-existent agent should return None");
}

#[test]
pub fn agent_heartbeat() {
    let test = TestDb::new();
    let repo = nkosi_db::AgentRepository::new(&test.db);

    let a1 = make_agent("a1", "host-alpha", AgentStatus::Online);
    repo.upsert(&a1).unwrap();

    let before = repo.get_by_id("a1").unwrap().unwrap().last_seen;

    std::thread::sleep(std::time::Duration::from_millis(10));

    repo.update_heartbeat("a1", 42, 5, 1).unwrap();

    let after = repo.get_by_id("a1").unwrap().unwrap().last_seen;
    assert!(after >= before, "Heartbeat should update last_seen");
}

#[test]
pub fn agent_mark_offline_stale() {
    let test = TestDb::new();
    let repo = nkosi_db::AgentRepository::new(&test.db);

    // Insert agent with old last_seen (simulate stale)
    let mut stale_agent = make_agent("a1", "host-alpha", AgentStatus::Online);
    stale_agent.last_seen = Utc::now() - chrono::Duration::hours(2);
    repo.upsert(&stale_agent).unwrap();

    // Insert fresh agent
    let fresh_agent = make_agent("a2", "host-beta", AgentStatus::Online);
    repo.upsert(&fresh_agent).unwrap();

    let count = repo.mark_offline_stale(300).unwrap();
    assert_eq!(count, 1, "Should mark 1 stale agent");

    let a1 = repo.get_by_id("a1").unwrap().unwrap();
    assert_eq!(a1.status, AgentStatus::Offline, "Stale agent should be marked Offline");

    let a2 = repo.get_by_id("a2").unwrap().unwrap();
    assert_eq!(a2.status, AgentStatus::Online, "Fresh agent should remain Online");
}

#[test]
pub fn events_with_agent_filter() {
    let test = TestDb::new();
    let agent_repo = nkosi_db::AgentRepository::new(&test.db);
    let event_repo = nkosi_db::EventRepository::new(&test.db);

    // Create agents
    let a1 = make_agent("a1", "host-alpha", AgentStatus::Online);
    let a2 = make_agent("a2", "host-beta", AgentStatus::Online);
    agent_repo.upsert(&a1).unwrap();
    agent_repo.upsert(&a2).unwrap();

    // Insert events for agent a1
    for i in 0..5 {
        let mut event = Event::new(EventType::FileCreated, "yara");
        event.file_path = Some(format!("/tmp/file_{}.txt", i));
        event.severity = if i < 2 { Severity::High } else { Severity::Low };
        event_repo.insert(&event).unwrap();
    }

    // Insert events for agent a2
    for i in 0..3 {
        let mut event = Event::new(EventType::NetworkConnection, "network");
        event.remote_ip = Some(format!("10.0.0.{}", i));
        event.severity = Severity::Critical;
        event_repo.insert(&event).unwrap();
    }

    // Query all events
    let all = agent_repo.get_events_filtered(None, None, None, 100).unwrap();
    assert_eq!(all.len(), 8, "Should have 8 total events");

    // Query by severity
    let critical = agent_repo.get_events_filtered(None, None, Some("Critical"), 100).unwrap();
    assert_eq!(critical.len(), 3, "Should have 3 critical events, got {}", critical.len());

    let high = agent_repo.get_events_filtered(None, None, Some("High"), 100).unwrap();
    assert_eq!(high.len(), 2, "Should have 2 high events, got {}", high.len());

    // Query with limit
    let limited = agent_repo.get_events_filtered(None, None, None, 3).unwrap();
    assert_eq!(limited.len(), 3, "Should respect limit");
}

#[test]
pub fn consolidated_stats() {
    let test = TestDb::new();
    let agent_repo = nkosi_db::AgentRepository::new(&test.db);
    let event_repo = nkosi_db::EventRepository::new(&test.db);

    // Create agents: 2 online, 1 offline
    let a1 = make_agent("a1", "host-alpha", AgentStatus::Online);
    let a2 = make_agent("a2", "host-beta", AgentStatus::Online);
    let mut a3 = make_agent("a3", "host-gamma", AgentStatus::Offline);
    a3.last_seen = Utc::now() - chrono::Duration::hours(2);
    agent_repo.upsert(&a1).unwrap();
    agent_repo.upsert(&a2).unwrap();
    agent_repo.upsert(&a3).unwrap();

    // Insert events
    for _ in 0..10 {
        let event = Event::new(EventType::FileCreated, "monitor");
        event_repo.insert(&event).unwrap();
    }

    // Insert some detections (high severity = threats)
    for _ in 0..3 {
        let mut event = Event::new(EventType::Detection, "yara");
        event.severity = Severity::High;
        event_repo.insert(&event).unwrap();
    }

    let stats = agent_repo.get_consolidated_stats().unwrap();
    assert_eq!(stats.total_agents, 3);
    assert_eq!(stats.online_agents, 2);
    assert_eq!(stats.offline_agents, 1);
    assert!(stats.total_events >= 13, "Should have at least 13 events (10 + 3 detections)");
    assert!(stats.total_threats >= 3, "Should have at least 3 threats");
}

#[test]
pub fn full_lifecycle() {
    let test = TestDb::new();
    let agent_repo = nkosi_db::AgentRepository::new(&test.db);
    let event_repo = nkosi_db::EventRepository::new(&test.db);

    // 1. Register 3 agents
    for i in 0..3 {
        let agent = make_agent(&format!("agent-{}", i), &format!("host-{}", i), AgentStatus::Online);
        agent_repo.upsert(&agent).unwrap();
    }

    // 2. Each agent sends heartbeats
    for i in 0..3 {
        agent_repo.update_heartbeat(&format!("agent-{}", i), 100 - (i as u32 * 10), i as u32, 0).unwrap();
    }

    // 3. Agents report events
    for i in 0..5 {
        let mut event = Event::new(EventType::FileCreated, &format!("monitor-{}", i % 3));
        event.file_path = Some(format!("/opt/app/file_{}.bin", i));
        event.severity = if i == 4 { Severity::High } else { Severity::Low };
        event_repo.insert(&event).unwrap();
    }

    // 4. Query consolidated view
    let stats = agent_repo.get_consolidated_stats().unwrap();
    assert_eq!(stats.total_agents, 3);
    assert!(stats.total_events >= 5);

    // 5. Mark stale agent offline
    let mut stale = make_agent("agent-0", "host-0", AgentStatus::Online);
    stale.last_seen = Utc::now() - chrono::Duration::hours(1);
    agent_repo.upsert(&stale).unwrap();
    let marked = agent_repo.mark_offline_stale(300).unwrap();
    assert_eq!(marked, 1);

    // 6. Verify final state
    let all = agent_repo.get_all().unwrap();
    let online_count = all.iter().filter(|a| a.status == AgentStatus::Online).count();
    let offline_count = all.iter().filter(|a| a.status == AgentStatus::Offline).count();
    assert_eq!(online_count, 2);
    assert_eq!(offline_count, 1);

    let stats = agent_repo.get_consolidated_stats().unwrap();
    assert_eq!(stats.online_agents, 2);
    assert_eq!(stats.offline_agents, 1);
}
