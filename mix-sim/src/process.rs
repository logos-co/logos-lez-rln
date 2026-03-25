use std::collections::VecDeque;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

const MAX_LOG_LINES: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Exited(i32),
    Failed(String),
}

pub struct ManagedProcess {
    pub child: Child,
    pub logs: VecDeque<String>,
    pub state: ProcessState,
    log_rx: mpsc::Receiver<String>,
    _log_task: tokio::task::JoinHandle<()>,
}

impl ManagedProcess {
    pub async fn spawn(mut cmd: Command) -> Result<Self, std::io::Error> {
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.stdin(Stdio::null());

        let mut child = cmd.spawn()?;

        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");

        let (tx, rx) = mpsc::channel(1000);

        let tx_stdout = tx.clone();
        let tx_stderr = tx;

        let log_task = tokio::spawn(async move {
            let mut stdout_reader = BufReader::new(stdout).lines();
            let mut stderr_reader = BufReader::new(stderr).lines();

            loop {
                tokio::select! {
                    line = stdout_reader.next_line() => {
                        match line {
                            Ok(Some(l)) => { let _ = tx_stdout.send(l).await; }
                            Ok(None) => break,
                            Err(_) => break,
                        }
                    }
                    line = stderr_reader.next_line() => {
                        match line {
                            Ok(Some(l)) => { let _ = tx_stderr.send(l).await; }
                            Ok(None) => {}
                            Err(_) => {}
                        }
                    }
                }
            }
        });

        Ok(Self {
            child,
            logs: VecDeque::with_capacity(MAX_LOG_LINES),
            state: ProcessState::Running,
            log_rx: rx,
            _log_task: log_task,
        })
    }

    pub fn drain_logs(&mut self) {
        while let Ok(line) = self.log_rx.try_recv() {
            if self.logs.len() >= MAX_LOG_LINES {
                self.logs.pop_front();
            }
            self.logs.push_back(line);
        }
    }

    pub fn check_status(&mut self) {
        if self.state == ProcessState::Running {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.state = ProcessState::Exited(status.code().unwrap_or(-1));
                }
                Ok(None) => {}
                Err(e) => {
                    self.state = ProcessState::Failed(e.to_string());
                }
            }
        }
    }

    pub fn is_running(&self) -> bool {
        self.state == ProcessState::Running
    }

    pub fn kill(&mut self) {
        let _ = self.child.start_kill();
    }

    pub fn last_log(&self) -> Option<&str> {
        self.logs.back().map(|s| s.as_str())
    }

    pub fn count_pattern(&self, pattern: &str) -> usize {
        self.logs.iter().filter(|l| l.contains(pattern)).count()
    }
}

pub async fn run_command(cmd: &str, args: &[&str], cwd: Option<&std::path::Path>) -> Result<String, String> {
    let mut command = Command::new(cmd);
    command.args(args);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let output = command.output().await.map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(format!("Command failed: {}\n{}", stderr, stdout))
    }
}

pub async fn check_port(port: u16) -> bool {
    tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .is_ok()
}

pub async fn wait_for_port(port: u16, timeout_secs: u64) -> bool {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);

    while start.elapsed() < timeout {
        if check_port(port).await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    false
}

pub async fn kill_process_on_port(port: u16) -> Result<(), String> {
    #[cfg(unix)]
    {
        let output = Command::new("lsof")
            .args(["-ti", &format!("tcp:{}", port)])
            .output()
            .await
            .map_err(|e| e.to_string())?;

        if output.status.success() {
            let pids = String::from_utf8_lossy(&output.stdout);
            for pid in pids.lines() {
                if let Ok(pid) = pid.trim().parse::<i32>() {
                    let _ = Command::new("kill").arg(pid.to_string()).output().await;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    Ok(())
}
