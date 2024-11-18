use std::io::{self, Error, ErrorKind};
use std::process::Command;

pub fn monitor_mode(interface: &str, channel: u8, bandwidth: u16) -> io::Result<()> {
    // Map bandwidth (u16) to corresponding chanspec
    let chanspec = match bandwidth {
        0 => "NOHT",
        20 => "HT20",
        40 => "HT40+",
        5 => "5MHz",
        10 => "10MHz",
        80 => "80MHz",
        160 => "160MHz",
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid bandwidth value: {}", bandwidth),
            ));
        }
    };

    // Bring interface down
    Command::new("sudo")
        .arg("ip")
        .arg("link")
        .arg("set")
        .arg("dev")
        .arg(interface)
        .arg("down")
        .status()?;

    // Bring interface down (ifconfig)
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

    // Bring interface up
    Command::new("sudo")
        .arg("ifconfig")
        .arg(interface)
        .arg("up")
        .status()?;

    // Set channel and bandwidth
    Command::new("sudo")
        .arg("iw")
        .arg(interface)
        .arg("set")
        .arg("channel")
        .arg(channel.to_string())
        .arg(chanspec)
        .status()?;

    Ok(())
}
