//! Everything that differs between Linux and Windows: file locations, showing a notification,
//! and starting the daemon at login.

use std::{fs, path::PathBuf, process::Command};

fn env_dir(var: &str, fallback_under_home: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(fallback_under_home))
}

fn home() -> PathBuf {
    #[cfg(windows)]
    let v = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let v = std::env::var_os("HOME");
    PathBuf::from(v.expect("home directory not set"))
}

pub fn config_dir() -> PathBuf {
    #[cfg(windows)]
    return env_dir("APPDATA", "AppData/Roaming").join("noti");
    #[cfg(not(windows))]
    env_dir("XDG_CONFIG_HOME", ".config").join("noti")
}

pub fn state_dir() -> PathBuf {
    #[cfg(windows)]
    return env_dir("LOCALAPPDATA", "AppData/Local").join("noti");
    #[cfg(not(windows))]
    env_dir("XDG_STATE_HOME", ".local/state").join("noti")
}

pub fn cache_dir() -> PathBuf {
    #[cfg(windows)]
    return env_dir("LOCALAPPDATA", "AppData/Local").join("noti").join("cache");
    #[cfg(not(windows))]
    env_dir("XDG_CACHE_HOME", ".cache").join("noti")
}

/// Writes a file only the current user can read (0600 on Unix; the per-user profile ACL on Windows).
pub fn write_private(p: &PathBuf, data: &str) {
    fs::create_dir_all(p.parent().unwrap()).expect("mkdir");
    fs::write(p, data).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(p, fs::Permissions::from_mode(0o600)).expect("chmod");
    }
}

/// Desktop notification. `icon` is a PNG path if one is cached.
pub fn show(title: &str, text: &str, icon: Option<&str>) {
    #[cfg(not(windows))]
    {
        let _ = Command::new("notify-send")
            .args(["-a", "noti", "-t", "10000", "-i", icon.unwrap_or("phone"), "--"])
            .arg(markup_escape(title))
            .arg(markup_escape(text))
            .status();
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let image = icon
            .map(|p| format!("<image placement=\"appLogoOverride\" src=\"{}\"/>", xml_escape(&format!("file:///{}", p.replace('\\', "/")))))
            .unwrap_or_default();
        // `long` keeps the toast on screen ~25 s (Windows only offers ~5 s or ~25 s); it also stays in the Action Center.
        let xml = format!(
            "<toast duration=\"long\"><visual><binding template=\"ToastGeneric\">{image}<text>{}</text><text>{}</text></binding></visual></toast>",
            xml_escape(title),
            xml_escape(text)
        );
        // The XML travels in an environment variable so no text is ever parsed as PowerShell code.
        const SCRIPT: &str = "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; \
            [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null; \
            $x = New-Object Windows.Data.Xml.Dom.XmlDocument; $x.LoadXml($env:NOTI_TOAST_XML); \
            $t = [Windows.UI.Notifications.ToastNotification]::new($x); \
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe').Show($t)";
        let _ = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", SCRIPT])
            .env("NOTI_TOAST_XML", xml)
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .status();
    }
}

#[cfg(not(windows))]
fn markup_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(windows)]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Start the daemon automatically at login. Returns a human-readable summary.
pub fn install_autostart() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        let cmd = format!("powershell.exe -NoProfile -WindowStyle Hidden -Command \"& '{}' run\"", exe.display());
        let ok = Command::new("reg")
            .args(["add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "noti-daemon", "/t", "REG_SZ", "/d", &cmd, "/f"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok { Ok("added to the current user's Run key; it starts at next login".into()) } else { Err("reg add failed".into()) }
    }
    #[cfg(not(windows))]
    {
        let unit = home().join(".config/systemd/user/noti-daemon.service");
        let text = format!(
            "[Unit]\nDescription=noti laptop daemon\nAfter=network-online.target graphical-session.target\nWants=network-online.target\n\n\
             [Service]\nExecStart={} run\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=default.target\n",
            exe.display()
        );
        fs::create_dir_all(unit.parent().unwrap()).map_err(|e| e.to_string())?;
        fs::write(&unit, text).map_err(|e| e.to_string())?;
        let ok = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()
            .and_then(|_| Command::new("systemctl").args(["--user", "enable", "--now", "noti-daemon"]).status())
            .map(|s| s.success())
            .unwrap_or(false);
        if ok { Ok(format!("systemd user service installed ({})", unit.display())) } else { Err("systemctl failed".into()) }
    }
}
