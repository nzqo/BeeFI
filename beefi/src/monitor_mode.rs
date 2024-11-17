use std::process::Command;

pub fn setup_monitor_mode(interface: &str, channel: u8) -> std::io::Result<()> {
    // Set the interface down
    Command::new("sudo")
        .arg("ifconfig")
        .arg(interface)
        .arg("down")
        .status()?;

    // Set monitor mode
    Command::new("sudo")
        .arg("iwconfig")
        .arg(interface)
        .arg("mode")
        .arg("monitor")
        .status()?;

    // Set the desired channel
    Command::new("sudo")
        .arg("iwconfig")
        .arg(interface)
        .arg("channel")
        .arg(channel.to_string())
        .status()?;

    // Bring the interface up
    Command::new("sudo")
        .arg("ifconfig")
        .arg(interface)
        .arg("up")
        .status()?;

    Ok(())
}
