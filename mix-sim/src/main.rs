mod config;
mod modules;
mod orchestrator;
mod phases;
mod process;
mod tui;

use crate::config::Paths;
use crate::tui::{app::App, ui};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    // Determine project root
    let rln_project = std::env::var("RLN_PROJECT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // Try to find it relative to current dir or executable
            let candidates = [
                PathBuf::from("."),
                PathBuf::from(".."),
                std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                    .unwrap_or_default(),
            ];

            for candidate in candidates {
                let full = candidate.join("logos-delivery");
                if full.exists() {
                    return candidate.canonicalize().unwrap_or(candidate);
                }
            }

            PathBuf::from(".")
        });

    let paths = Paths::new(rln_project);

    // Set up terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = Arc::new(Mutex::new(App::new(paths)));

    // Spawn orchestration task
    let orchestration_app = Arc::clone(&app);
    let orchestration_handle = tokio::spawn(async move {
        if let Err(e) = orchestrator::run_orchestration(orchestration_app).await {
            eprintln!("Orchestration error: {}", e);
        }
    });

    // Main event loop
    let result = run_event_loop(&mut terminal, Arc::clone(&app)).await;

    // Shutdown
    {
        let mut app = app.lock().await;
        app.shutdown();
    }

    // Wait for orchestration to finish
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), orchestration_handle).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: Arc<Mutex<App>>,
) -> color_eyre::Result<()> {
    loop {
        // Draw UI
        {
            let app = app.lock().await;
            terminal.draw(|f| ui::render(f, &app))?;
        }

        // Check for quit
        {
            let app = app.lock().await;
            if app.should_quit {
                return Ok(());
            }
        }

        // Poll events with timeout
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    let mut app = app.lock().await;
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            app.should_quit = true;
                        }
                        KeyCode::Char('j') | KeyCode::Down => {
                            app.select_next_node();
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            app.select_prev_node();
                        }
                        KeyCode::Tab => {
                            app.toggle_log_panel();
                        }
                        KeyCode::PageUp => {
                            app.scroll_log_up();
                        }
                        KeyCode::PageDown => {
                            app.scroll_log_down();
                        }
                        _ => {}
                    }
                }
            }
        }

        // Tick app state
        {
            let mut app = app.lock().await;
            app.tick();
        }
    }
}
