
use anyhow::Result;
use nekoton_abi::*;


pub mod htlc_forwarder_contract;

use crate::htlc::htlc_forwarder_contract::{RouteFunctionInput, SettleFunctionInput};

use ton_abi::Token;

#[derive(Copy, Clone)]
pub struct HTLC<'a>(pub ExecutionContext<'a>);

impl HTLC<'_> {

    pub fn get_details(&self) -> Result<Vec<ton_abi::Token>> {
        let inputs = Vec::new(); //[0u32.token_value().named("answerId")];
        let ExecutionOutput {
            tokens,
            result_code,
        } = self
            .0
            .run_local(htlc_forwarder_contract::get_details(), &inputs)?;
        // TODO: replace unwrap
        match tokens {
            None => {
                panic!("No data. Error {}", result_code)
            }
            Some(result) => Ok(result),
        }
    }

    pub fn refund(&self) -> Result<Vec<Token>> {
        let inputs = Vec::new();
        let ExecutionOutput {
            tokens,
            result_code,
        } = self
            .0
            .run_local(htlc_forwarder_contract::refund(), &inputs)?;
        match tokens {
            None => {
                panic!("The contract couldn't execute. Refund debug info:\n   {}", result_code);
            }
            Some(result) => Ok(result),
        }
    }

    pub fn settle(&self, preimage: ton_types::UInt256) -> Result<()> {
        let input = SettleFunctionInput { preimage }.pack();
        let ExecutionOutput {
            tokens,
            result_code,
        } = self.0.run_local(htlc_forwarder_contract::settle(), &input)?;
        match tokens {
            None => {
                panic!("The contract couldn't execute. Settle debug info:\n   {}", result_code);
            }
            Some(result) => {
                println!("Settle debug info:\n   {:?}", result);
            }
        }
        Ok(())
    }

    pub fn route(
        &self,
        counterparty: ton_block::MsgAddressInt,
        amount: u128,
        hashlock: ton_types::UInt256,
        timelock: u64,
    ) -> Result<()> {
        let input = RouteFunctionInput {
            counterparty,
            amount,
            hashlock,
            timelock,
        }
        .pack();
        let ExecutionOutput {
            tokens,
            result_code,
        } = self.0.run_local(htlc_forwarder_contract::route(), &input)?;
        match tokens {
            None => {
                println!("Route debug info:\n   {}", result_code);
            }
            Some(result) => {
                println!("Route debug info:\n   {:?}", result);
            }
        }
        Ok(())
    }
}
