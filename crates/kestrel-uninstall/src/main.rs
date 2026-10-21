//! `kestrel-uninstall.exe`: GUI front end for removing the Kestrel agent
//! with the device's uninstall token. Windows only; elsewhere it is a stub
//! so the workspace still builds and tests on Linux.

// A GUI program: no console window (usage goes to a message box).
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    #[cfg(windows)]
    std::process::exit(kestrel_uninstall::win::gui::main());

    #[cfg(not(windows))]
    {
        eprintln!("kestrel-uninstall: Windows only");
        std::process::exit(2);
    }
}
