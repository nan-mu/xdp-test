use aya::{programs::{Xdp, XdpFlags}, maps::ProgramArray, Ebpf};
use anyhow::Result;
use log::info;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    info!("Loading Ebpf program from ./target");
    let mut bpf = Ebpf::load_file("./target/xdp.o")?;
    
    info!("Loading program array map");
    let mut prog_array = ProgramArray::try_from(
        bpf.take_map("prog_array")
            .expect("Failed to find 'prog_array' map")
    ).unwrap();
    
    info!("Loading child XDP program");
    let child: &mut Xdp = bpf.program_mut("child")
        .expect("Failed to find 'child' program")
        .try_into()?;
    child.load()?;
    let child_fd= child.fd().unwrap();
    
    // Add the child program to the program array for tail calls
    info!("Adding child program to program array");
    prog_array.set(0, &child_fd, 0)?;
    
    // Get references to parent and child XDP programs
    info!("Loading parent XDP program");
    let parent: &mut Xdp = bpf.program_mut("parent")
        .expect("Failed to find 'parent' program").try_into()?;
    parent.load()?;
    // Attach the parent XDP program to eth0
    info!("Attaching parent XDP program to eth0");
    parent.attach("enp0s8", XdpFlags::default())?;

    info!("XDP programs loaded and running. Press Ctrl+C to exit.");
    
    // Wait for Ctrl+C signal
    signal::ctrl_c().await?;
    
    info!("Exiting...");
    
    Ok(())
}