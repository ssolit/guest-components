// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::Attester;
use anyhow::*;
use az_tdx_vtpm::vtpm::Quote as TpmQuote;
use az_tdx_vtpm::{hcl, imds, is_tdx_cvm, report, vtpm};
use kbs_types::Tee;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::result::Result::Ok;

pub fn detect_platform() -> bool {
    match is_tdx_cvm() {
        Ok(tdx) => tdx,
        Err(err) => {
            debug!("Couldn't perform Azure TDX platform detection: {err}");
            false
        }
    }
}

#[derive(Debug, Default)]
pub struct AzTdxVtpmAttester;

#[derive(Serialize, Deserialize)]
struct Evidence {
    tpm_quote: TpmQuote,
    hcl_report: Vec<u8>,
    td_quote: Vec<u8>,
}

#[async_trait::async_trait]
impl Attester for AzTdxVtpmAttester {
    async fn get_evidence(&self, report_data: Vec<u8>) -> Result<String> {
        // let str = "report_data".to_string(); // works
        // let str = "report_data0".to_string(); // doesn't work
        // let str = "report_dat".to_string(); // works
        let str = "report_dataa".to_string(); // doesn't work
        let report_data = str.as_bytes();

        println!("\n using AzTdxVtpmAttester");
        println!("here0\n");
        println!("report_data: {:?}", report_data);
        println!("report_data_len: {:?}", report_data.len());
        let hcl_report_bytes = vtpm::get_report_with_report_data(&report_data)?;
        // let hcl_report_bytes = vtpm::get_report_with_report_data(&"report_data".to_string().as_bytes())?; // this makes the function not break 
        println!("here1");
        let hcl_report = hcl::HclReport::new(hcl_report_bytes.clone())?;
        println!("here2");
        let td_report = hcl_report.try_into()?;
        println!("here3");
        let td_quote_bytes = imds::get_td_quote(&td_report)?;
        println!("here4");
        let tpm_quote = vtpm::get_quote(&report_data)?;
        println!("here5");
        let evidence = Evidence {
            tpm_quote,
            hcl_report: hcl_report_bytes,
            td_quote: td_quote_bytes,
        };
        Ok(serde_json::to_string(&evidence)?)
    }

    async fn extend_runtime_measurement(
        &self,
        event_digest: Vec<u8>,
        register_index: u64,
    ) -> Result<()> {
        let sha256_digest: [u8; 32] = event_digest
            .as_slice()
            .try_into()
            .context("expected sha256 digest")?;
        if register_index > 23 {
            bail!("Invalid PCR index: {}", register_index);
        }
        let pcr: u8 = register_index as u8;
        info!("Extending PCR {} with {}", pcr, hex::encode(sha256_digest));
        vtpm::extend_pcr(pcr, &sha256_digest)?;

        Ok(())
    }

    async fn get_type(&self) -> Tee {
        Tee::AzTdxVtpm
    }
}
