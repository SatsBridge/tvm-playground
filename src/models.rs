
use ed25519_dalek::Keypair;
use nekoton_abi::{PackAbiPlain, UnpackAbiPlain};
use nekoton_utils::{serde_address};
use serde::{Deserialize, Serialize};
use ton_abi::{Function, Token};
use ton_block::{AccountStuff, MsgAddressInt};
use ton_types::{BuilderData, Cell, UInt256};

#[derive(Debug, Clone, PackAbiPlain)]
pub struct HTLCRoutingRequest {
    #[abi(name = "_incoming")]
    pub incoming: bool,
    #[abi(name = "_counterparty", address)]
    pub counterparty: MsgAddressInt,
    #[abi(name = "_hashlock", uint256)]
    pub hashlock: UInt256,
    #[abi(name = "_timelock", uint64)]
    pub timelock: u64,
}

#[derive(PackAbiPlain, UnpackAbiPlain, Debug, Clone)]
pub struct Transfer {
    #[abi]
    pub amount: u128,
    #[abi]
    pub recipient: MsgAddressInt,
    #[abi(name = "deployWalletValue")]
    pub deploy_wallet_value: u128,
    #[abi(name = "remainingGasTo")]
    pub remaining_gas_to: MsgAddressInt,
    #[abi]
    pub notify: bool,
    #[abi]
    pub payload: Cell,
}

pub struct PayloadMeta {
    pub payload: BuilderData,
    pub destination: MsgAddressInt,
}

pub struct SendData {
    pub payload_meta: PayloadMeta,
    pub signer: Keypair,
    pub sender_addr: MsgAddressInt,
}

impl SendData {
    pub fn new(payload_meta: PayloadMeta, signer: Keypair, sender_addr: MsgAddressInt) -> Self {
        Self {
            payload_meta,
            signer,
            sender_addr,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CreateAccountParams {
    pub nonce: u32,
}

#[derive(Serialize, Deserialize)]
pub struct EverWalletInfo {
    #[serde(rename = "createAccountParams")]
    pub create_account_params: CreateAccountParams,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GenericDeploymentInfo {
    #[serde(with = "serde_address")]
    pub address: MsgAddressInt,
}

pub struct PayloadGenerator {
    pub htlc: AccountStuff,
    pub htlc_fun: Function,
    pub destination: MsgAddressInt,
    pub htlc_request: Vec<Token>,
}

impl PayloadGenerator {
    pub fn generate_payload_meta(&mut self) -> PayloadMeta {
        /*
        let payload = &self
            .htlc_fun
            .run_local(
                &SimpleClock,
                self.htlc.clone(),
                &self.htlc_request,
            )
            .map_err(|x| {
                log::error!("run_local error {:#?}", x);
                x
            })
            .ok();
        */

        //let payload_token = self.tokens.htlc_request.get_mut(5).unwrap();
        //payload_token.value = payload.token_value();

        PayloadMeta {
            payload: self
                .htlc_fun
                .encode_internal_input(&self.htlc_request)
                .unwrap(),
            destination: self.destination.clone(),
        }
    }
}
