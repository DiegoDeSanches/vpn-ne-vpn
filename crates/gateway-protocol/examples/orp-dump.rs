use std::io::{self, Read};

use onionroute_gateway_protocol::debug::DebugDecoder;
use onionroute_gateway_protocol::limits::ABSOLUTE_MAX_FRAME_SIZE;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut decoder = DebugDecoder::new(ABSOLUTE_MAX_FRAME_SIZE)?;
    let mut input = io::stdin().lock();
    let mut chunk = [0u8; 4096];
    loop {
        let read = input.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let mut offset = 0usize;
        while offset < read {
            let (consumed, summary) = decoder.push(&chunk[offset..read])?;
            if consumed == 0 {
                return Err("decoder made no progress".into());
            }
            offset += consumed;
            if let Some(summary) = summary {
                println!("{summary}");
            }
        }
    }
    Ok(())
}
