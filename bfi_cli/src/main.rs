use bfi_lib::{extract_from_capture, extract_from_packet};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about, long_about = None, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

/**
 * Available CLI commands
 */
#[derive(Subcommand)]
enum Commands {
    /// Extract BFA angles and other data from a pcap capture
    Extract {
        /// pcap input file
        #[arg(short = 'f', long, value_name = "FILE")]
        pcap_file: PathBuf,

        /// parquet output file
        #[arg(short, long, value_name = "OUTFILE")]
        out_file: PathBuf,

        /// Whether to print extracted variables
        #[arg(short, long)]
        print: bool,
    },
    // starts live capture of bfa
    CAPTURE {
        /// Chose interface to be used
        #[arg(short = 'i', long, value_name = "INTERFACE")]
        interface: String,

        /// parquet output file
        #[arg(short, long, value_name = "OUTFILE")]
        out_file: PathBuf,

        /// Whether to print extracted variables
        #[arg(short, long)]
        print: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Extract {
            pcap_file,
            out_file,
            print,
        }) => {
            let extracted_data = extract_from_capture(pcap_file);

            if print {
                print!("Extracted data: {:?}\n", extracted_data)
            }

            if let Err(e) = extracted_data.to_parquet(out_file) {
                print!("Writing to parquet failed with error: {}", e);
            }
            println!("Data extraction completed!\n");
        }

        Some(Commands::CAPTURE {
            interface,
            out_file,
            print,
        }) => {
            println!("Starting live capture...");

            let device_name = interface;
            match pcap::Device::list() {
                Ok(devices) => {
                    if let Some(device) = devices.into_iter().find(|d| d.name == device_name) {
                        println!("Selected device: {}", device.name);

                        // for storing the captured and ürocessed data
                        let mut packet_buffer = Vec::new();
                        let batch_size = 10;

                        // open a capture on the device with inputted interface
                        match pcap::Capture::from_device(device)
                            .unwrap()
                            .promisc(true)
                            .open()
                        {
                            Ok(mut cap) => {
                                println!("Capture started on device: {}", device_name);

                                // filter for Action No ACK management frames
                                let filter = "ether[0] == 0xe0";
                                match cap.filter(filter, true) {
                                    Ok(_) => println!("Filter applied: {}", filter),
                                    Err(e) => eprintln!("Failed to apply filter: {}", e),
                                }

                                // Loop over captured packets
                                while let Ok(packet) = cap.next_packet() {
                                    // Extract data from the packet using your extraction function
                                    let result = extract_from_packet(&packet);
                                    println!("length: {:?}", result.bfa_angles);
                                    // Add the extracted packet data to the buffer
                                    packet_buffer.push(result);

                                    // Periodically write to Parquet when buffer reaches the batch size
                                    if packet_buffer.len() >= batch_size {
                                        println!("Writing packet data to Parquet...");
                                        for packet_data in &packet_buffer {
                                            if let Err(e) = packet_data.to_parquet(out_file.clone())
                                            {
                                                eprintln!("Failed to write to Parquet: {}", e);
                                            } else {
                                                println!(
                                                    "Successfully wrote to {}",
                                                    out_file.display()
                                                );
                                            }
                                        }
                                        packet_buffer.clear(); // Clear the buffer after writing
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to open capture on device: {}", e);
                            }
                        }
                    } else {
                        println!("Device {} not found.", device_name);
                    }
                    println!("Live capture and data extraction completed!\n");
                }
                Err(e) => {
                    eprintln!("Failed to list network interfaces: {}", e);
                }
            }

            println!("Live capture and data processing completed!\n");
        }
        None => {}
    }
}
