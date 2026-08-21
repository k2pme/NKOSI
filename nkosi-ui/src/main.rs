use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io;
use std::time::Duration;

mod app;
use app::App;

fn main() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new()?;
    
    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => {
                        app.quit();
                    }
                    KeyCode::Tab => {
                        app.next_tab();
                    }
                    KeyCode::BackTab => {
                        app.previous_tab();
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.next_item();
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.previous_item();
                    }
                    KeyCode::Enter => {
                        app.select_item();
                    }
                    KeyCode::Char('r') => {
                        app.refresh()?;
                    }
                    KeyCode::Char('s') => {
                        app.start_scan();
                    }
                    KeyCode::Char('l') => {
                        app.show_logs();
                    }
                    KeyCode::Left => {
                        app.previous_scan_path();
                    }
                    KeyCode::Right => {
                        app.next_scan_path();
                    }
                    _ => {}
                }
            }
        }

        app.poll_scan();
        
        if app.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn ui(f: &mut Frame, app: &mut App) {
    let size = f.area();
    
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(size);
    
    let header = Paragraph::new("NKOSI Security Dashboard")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL).title("NKOSI"));
    f.render_widget(header, chunks[0]);
    
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(20),
            Constraint::Min(0),
        ])
        .split(chunks[1]);
    
    let sidebar_items: Vec<ListItem> = app.tabs.iter().enumerate().map(|(i, tab)| {
        let style = if i == app.current_tab {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        ListItem::new(Line::from(Span::styled(tab.clone(), style)))
    }).collect();
    
    let sidebar = List::new(sidebar_items)
        .block(Block::default().borders(Borders::ALL).title("Menu"));
    f.render_widget(sidebar, content_chunks[0]);
    
    match app.current_tab {
        0 => render_dashboard(f, app, content_chunks[1]),
        1 => render_scan(f, app, content_chunks[1]),
        2 => render_quarantine(f, app, content_chunks[1]),
        3 => render_logs(f, app, content_chunks[1]),
        4 => render_settings(f, app, content_chunks[1]),
        _ => render_dashboard(f, app, content_chunks[1]),
    }
    
    let footer_text = "q: Quit | Tab: Switch | j/k: Navigate | ←/→: Scan path | s: Scan | r: Refresh | l: Logs";
    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::Gray))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[2]);
}

fn render_dashboard(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .split(area);
    
    let stats_text = format!(
        "Statistiques:\n  Événements: {}\n  Menaces: {}\n  Quarantaine: {}",
        app.stats.total_events,
        app.stats.total_threats,
        app.stats.quarantine_items
    );
    
    let stats = Paragraph::new(stats_text)
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL).title("Statistiques"));
    f.render_widget(stats, chunks[0]);
    
    let events: Vec<ListItem> = app.events.iter().map(|event| {
        let severity_color = match event.severity {
            nkosi_common::types::Severity::Critical => Color::Red,
            nkosi_common::types::Severity::High => Color::Yellow,
            nkosi_common::types::Severity::Medium => Color::Cyan,
            nkosi_common::types::Severity::Low => Color::Green,
            nkosi_common::types::Severity::Info => Color::Gray,
        };
        
        ListItem::new(Line::from(vec![
            Span::styled(
                format!("[{}] ", event.timestamp),
                Style::default().fg(Color::Gray)
            ),
            Span::styled(
                format!("{:?} ", event.event_type),
                Style::default().fg(severity_color)
            ),
            Span::styled(
                event.source_module.clone(),
                Style::default().fg(Color::White)
            ),
        ]))
    }).collect();
    
    let events_list = List::new(events)
        .block(Block::default().borders(Borders::ALL).title("Événements récents"));
    f.render_widget(events_list, chunks[1]);
}

fn render_scan(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);
    
    let scan_path = Paragraph::new(format!(
        "{}  [←/→ pour changer, chemins surveillés: {}]",
        app.scan_path,
        app.watched_paths.join(", ")
    ))
    .style(Style::default().fg(Color::White))
    .block(Block::default().borders(Borders::ALL).title("Chemin à scanner"));
    f.render_widget(scan_path, chunks[0]);
    
    let results_text = if app.scan_results.is_empty() {
        "Appuyez sur 's' pour démarrer un scan".to_string()
    } else {
        app.scan_results.join("\n")
    };
    
    let results = Paragraph::new(results_text)
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL).title("Résultats du scan"))
        .wrap(Wrap { trim: true });
    f.render_widget(results, chunks[1]);
}

fn render_quarantine(f: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app.quarantine_items.iter().map(|item| {
        ListItem::new(Line::from(vec![
            Span::styled(
                format!("[{}] ", item.id),
                Style::default().fg(Color::Gray)
            ),
            Span::styled(
                item.original_path.clone(),
                Style::default().fg(Color::Yellow)
            ),
            Span::styled(
                format!(" (score: {})", item.score),
                Style::default().fg(Color::Red)
            ),
        ]))
    }).collect();
    
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Quarantine"));
    f.render_widget(list, area);
}

fn render_logs(f: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app.logs.iter().map(|log| {
        ListItem::new(Line::from(vec![
            Span::styled(
                format!("[{}] ", log.timestamp),
                Style::default().fg(Color::Gray)
            ),
            Span::styled(
                format!("{:?} ", log.event_type),
                Style::default().fg(Color::Cyan)
            ),
            Span::styled(
                log.source_module.clone(),
                Style::default().fg(Color::White)
            ),
        ]))
    }).collect();
    
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Logs"));
    f.render_widget(list, area);
}

fn render_settings(f: &mut Frame, app: &mut App, area: Rect) {
    let settings_text = format!(
        "Paramètres:\n\n  Chemin base de données: {}\n  Chemin quarantaine: {}\n  Intervalle update: {}h",
        app.config.agent.db_path.display(),
        app.config.quarantine.path.display(),
        app.config.threat_intel.update_interval_hours
    );
    
    let settings = Paragraph::new(settings_text)
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL).title("Paramètres"));
    f.render_widget(settings, area);
}
