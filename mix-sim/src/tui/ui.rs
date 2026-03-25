use crate::config::NodeMode;
use crate::phases::nodes::NodeState;
use crate::tui::app::{App, LogPanel};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, Wrap},
    Frame,
};

pub fn render(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Main area
            Constraint::Length(1), // Footer
        ])
        .split(frame.area());

    render_header(frame, app, chunks[0]);
    render_main(frame, app, chunks[1]);
    render_footer(frame, chunks[2]);
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let phase_num = app.phase_number();
    let progress = if phase_num > 0 {
        (phase_num as f64 / 7.0).min(1.0)
    } else {
        0.0
    };

    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Mix Simulation "))
        .gauge_style(Style::default().fg(Color::Cyan))
        .percent((progress * 100.0) as u16)
        .label(format!("[{}/7] {}", phase_num, app.phase));

    frame.render_widget(gauge, area);
}

fn render_main(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),    // Node table
            Constraint::Length(12), // Log panel
        ])
        .split(area);

    render_node_table(frame, app, chunks[0]);
    render_log_panel(frame, app, chunks[1]);
}

fn render_node_table(frame: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["Node", "Mode", "Port", "State", "Last Log"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app
        .nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let state_style = match &node.state {
                NodeState::Ready => Style::default().fg(Color::Green),
                NodeState::Failed(_) => Style::default().fg(Color::Red),
                NodeState::Initializing { .. } => Style::default().fg(Color::Yellow),
                _ => Style::default().fg(Color::Gray),
            };

            let state_symbol = match &node.state {
                NodeState::Ready => "●",
                NodeState::Failed(_) => "✗",
                NodeState::Initializing { .. } => "◐",
                NodeState::Starting => "○",
                _ => "○",
            };

            let mode_str = match node.config.mode {
                NodeMode::Core => "Core",
                NodeMode::Edge => "Edge",
            };

            let last_log = node
                .last_log()
                .map(|s| {
                    if s.len() > 40 {
                        format!("{}...", &s[..37])
                    } else {
                        s.to_string()
                    }
                })
                .unwrap_or_default();

            let row_style = if i == app.selected_node {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(format!("{}", node.config.index)),
                Cell::from(mode_str),
                Cell::from(format!("{}", node.config.tcp_port)),
                Cell::from(format!("{} {}", state_symbol, node.state)).style(state_style),
                Cell::from(last_log),
            ])
            .style(row_style)
        })
        .collect();

    // If no nodes yet, show placeholder
    let rows = if rows.is_empty() {
        vec![Row::new(vec![Cell::from("No nodes started yet")])]
    } else {
        rows
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(6),
            Constraint::Length(15),
            Constraint::Min(30),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Nodes "));

    frame.render_widget(table, area);
}

fn render_log_panel(frame: &mut Frame, app: &App, area: Rect) {
    let title = match &app.log_panel {
        LogPanel::Node(i) => format!(" Node {} Log ", i),
        LogPanel::Sequencer => " Sequencer Log ".to_string(),
        LogPanel::Global => " Global Log ".to_string(),
    };

    let logs: Vec<&str> = match &app.log_panel {
        LogPanel::Node(i) => {
            if let Some(node) = app.nodes.get(*i) {
                node.logs().collect()
            } else {
                vec![]
            }
        }
        LogPanel::Sequencer => {
            if let Some(ref p) = app.sequencer.process {
                p.logs.iter().map(|s| s.as_str()).collect()
            } else {
                vec![]
            }
        }
        LogPanel::Global => app.global_log.iter().map(|s| s.as_str()).collect(),
    };

    let visible_lines = (area.height as usize).saturating_sub(2);
    let total_lines = logs.len();
    let start = if total_lines > visible_lines {
        (total_lines - visible_lines).saturating_sub(app.log_scroll)
    } else {
        0
    };

    let lines: Vec<Line> = logs
        .iter()
        .skip(start)
        .take(visible_lines)
        .map(|s| Line::from(*s))
        .collect();

    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false });

    frame.render_widget(paragraph, area);
}

fn render_footer(frame: &mut Frame, area: Rect) {
    let text = Line::from(vec![
        Span::raw(" q"),
        Span::styled(": quit", Style::default().fg(Color::DarkGray)),
        Span::raw(" │ "),
        Span::raw("↑↓/jk"),
        Span::styled(": select", Style::default().fg(Color::DarkGray)),
        Span::raw(" │ "),
        Span::raw("Tab"),
        Span::styled(": switch log", Style::default().fg(Color::DarkGray)),
        Span::raw(" │ "),
        Span::raw("PgUp/PgDn"),
        Span::styled(": scroll", Style::default().fg(Color::DarkGray)),
    ]);

    let paragraph = Paragraph::new(text);
    frame.render_widget(paragraph, area);
}
