// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use attester::*;
use clap::Parser;
use std::io::Read;
use tokio::fs;
use std::any::type_name;

#[derive(Debug, Parser)]
#[command(author)]
enum Cli {
    /// Read report data from stdin. The input must be 64 bytes in length
    Stdio,

    /// Read report data from commandline. If the length of input is longer than
    /// 64 bytes, the input will be truncated. If shorter, it will be padded by `\0`.
    Commandline { data: String },

    /// Read report data from the given file. If the length of input is longer than
    /// 64 bytes, the input will be truncated. If shorter, it will be padded by `\0`.
    File { path: String },
}

#[tokio::main]
async fn main() {
    println!();
    // report_data on all platforms is 64 bytes length.
    let mut report_data = vec![0u8; 64];

    let cli = Cli::parse();

    let tee = detect_tee_type();
    println!("TEE type: {:?}", tee);

    let attester: BoxedAttester = tee.try_into().expect("create attester failed");
    println!("Attester type: {:?}", attester.get_type().await);

    match cli {
        Cli::Stdio => std::io::stdin()
            .read_exact(&mut report_data)
            .expect("read input failed"),
        Cli::Commandline { data } => {
            let len = data.len().min(64);
            report_data[..len].copy_from_slice(&data.as_bytes()[..len]);
        }
        Cli::File { path } => {
            let content = fs::read(path)
                .await
                .expect("read report data from file failed");
            let len = content.len().min(64);
            report_data[..len].copy_from_slice(&content[..len]);
        }
    }

    let evidence = attester
        .get_evidence(report_data)
        .await
        .expect("get evidence failed");
    println!("{evidence}");
}

fn print_type_of<T>(_: &T) {
    println!("Type: {}", type_name::<T>());
}
