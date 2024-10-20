use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use bigdecimal::BigDecimal;
use std::str::FromStr;

use bigdecimal::num_bigint::ToBigInt;
use clap::Parser;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer, SIGNATURE_LENGTH};

use nekoton::core::models::{Expiration, TokenWalletVersion};

use nekoton::core::token_wallet::{RootTokenContractState, TokenWalletContractState};
use nekoton::core::ton_wallet::{compute_address, Gift, TransferAction, WalletType};
use nekoton::crypto::{derive_from_phrase, UnsignedMessage};
use nekoton::transport::models::ExistingContract;
use nekoton_abi::num_bigint::BigUint;
use nekoton_abi::PackAbiPlain;
use nekoton_abi::{pack_into_cell, BigUint128, MessageBuilder};
use nekoton_contracts::tip3_1;
use nekoton_utils::now_sec_u64;
use nekoton_utils::{SimpleClock, TrustMe};
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use rust_decimal::Decimal;
use ton_block::{GetRepresentationHash, MsgAddressInt};
use ton_types::{SliceData, UInt256};
use url::Url;

use crate::htlc::htlc_forwarder_contract;
use hex::{decode, encode};

use rand::distributions::Alphanumeric;
use rand::Rng;
use sha2::digest::Output;
use sha2::{Digest, Sha256};

pub mod abi;
pub mod build_payload;
pub mod hash;
pub mod htlc;
pub mod models;

const DEFAULT_ABI_VERSION: ton_abi::contract::AbiVersion = ton_abi::contract::ABI_VERSION_2_0;

const DEFAULT_EXPIRATION_TIMEOUT: u32 = 120; // sec
const INITIAL_BALANCE: u64 = 100_000_000; // 0.1 EVER
const ATTACHED_AMOUNT: u64 = 200_000_000; // 0.2 EVER

const RPC_ENDPOINT: &str = "https://extension-api.broxus.com/rpc";

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: SubCommand,
    #[clap(short, long)]
    keystore: PathBuf,
}

#[derive(clap::Subcommand)]
enum SubCommand {
    /// Get public key
    GetPubkey,

    /// Get address
    GetAddress {
        #[arg(short, long, default_value_t = ("EverWallet").to_string())]
        /// Wallet type
        wallet: String,
    },

    /// Get balance
    GetBalance {
        #[arg(short, long, default_value_t = ("EverWallet").to_string())]
        /// Wallet type
        wallet: String,
    },

    /// Send transaction
    SendTransaction {
        #[arg(short, long, default_value_t = ("EverWallet").to_string())]
        /// Wallet type
        wallet: String,

        #[arg(long)]
        /// Amount to send
        amount: String,

        #[arg(long)]
        /// Destination address
        address: String,
    },

    /// Get balance
    GetTokenBalance {
        #[arg(short, long, default_value_t = ("EverWallet").to_string())]
        /// Wallet type
        wallet: String,

        #[arg(short, long)]
        /// Token name (WEVER, USDT, USDC, DAI)
        token: String,

        #[arg(short, long)]
        address: Option<String>,
    },

    /// Send token transaction
    SendTokenTransaction {
        #[arg(short, long, default_value_t = ("EverWallet").to_string())]
        /// Wallet type
        wallet: String,

        #[arg(long)]
        /// Amount to send
        amount: String,

        #[arg(long)]
        /// Destination address
        address: String,

        #[arg(short, long)]
        /// Token name (WEVER, USDT, USDC, DAI)
        token: String,
    },
    /// Send token transaction
    SendInboundHtlcTransaction {
        #[arg(short, long, default_value_t = ("EverWallet").to_string())]
        /// Wallet type
        wallet: String,

        #[arg(long)]
        /// Amount to send
        amount: String,

        #[arg(long)]
        /// Destination address
        counterparty: String,

        #[arg(short, long)]
        /// Token name (WEVER, USDT, USDC, DAI)
        token: String,

        #[arg(long)]
        /// A secret to hash
        preimage: Option<String>,
        #[arg(short, long, default_value_t = 900)]
        /// A secret to hash
        expire: u64,
    },
    /// Send token transaction
    SendOutboundHtlcTransaction {
        #[arg(long)]
        /// Amount to send
        amount: String,

        #[arg(long)]
        /// Destination address
        counterparty: String,

        #[arg(short, long)]
        /// Token name (WEVER, USDT, USDC, DAI)
        token: String,

        #[arg(long)]
        /// A secret to hash
        hashlock: Option<String>,

        #[arg(long, default_value_t = 120)]
        timelock: u64,
    },
    SettleHtlc {
        #[arg(long)]
        /// A secret to hash
        preimage: String,
    },
    RefundHtlc,
    /// Get contract state
    GetContractState {
        #[arg(long)]
        /// Contract address
        address: String,
    },
    /// Deploy wallet
    Deploy {
        #[arg(short, long, default_value_t = ("EverWallet").to_string())]
        /// Wallet type
        wallet: String,
    },

    /// List of Everscale Wallets
    GetWallets,

    /// List of tokens
    GetTokens,
}

struct TokenDetails<'a> {
    ticker: &'a str,
    decimals: u8,
    factor: BigDecimal,
    root: MsgAddressInt,
}

enum Token {
    Usdt,
    Usdc,
    Dai,
    Wever,
    Sat,
}

impl FromStr for Token {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Token> {
        match input {
            "WEVER" => Ok(Token::Wever),
            "USDT" => Ok(Token::Usdt),
            "USDC" => Ok(Token::Usdc),
            "DAI" => Ok(Token::Dai),
            "SAT" => Ok(Token::Sat),
            _ => bail!("Missing attribute: {}", input),
        }
    }
}

impl Token {
    fn details(&self) -> TokenDetails {
        match *self {
            Token::Wever => TokenDetails {
                ticker: "WEVER",
                decimals: 9,
                factor: BigDecimal::from_u128(1_000_000_000).trust_me(),
                root: MsgAddressInt::from_str(
                    "0:a49cd4e158a9a15555e624759e2e4e766d22600b7800d891e46f9291f044a93d",
                )
                .trust_me(),
            },
            Token::Usdt => TokenDetails {
                ticker: "USDT",
                decimals: 6,
                factor: BigDecimal::from_u128(1_000_000).trust_me(),
                root: MsgAddressInt::from_str(
                    "0:a519f99bb5d6d51ef958ed24d337ad75a1c770885dcd42d51d6663f9fcdacfb2",
                )
                .trust_me(),
            },
            Token::Usdc => TokenDetails {
                ticker: "USDC",
                decimals: 6,
                factor: BigDecimal::from_u128(1_000_000).trust_me(),
                root: MsgAddressInt::from_str(
                    "0:c37b3fafca5bf7d3704b081fde7df54f298736ee059bf6d32fac25f5e6085bf6",
                )
                .trust_me(),
            },
            Token::Dai => TokenDetails {
                ticker: "DAI",
                decimals: 18,
                factor: BigDecimal::from_u128(1_000_000_000_000_000_000).trust_me(),
                root: MsgAddressInt::from_str(
                    "0:eb2ccad2020d9af9cec137d3146dde067039965c13a27d97293c931dae22b2b9",
                )
                .trust_me(),
            },
            Token::Sat => TokenDetails {
                ticker: "SAT",
                decimals: 13,
                factor: BigDecimal::from_u128(10_000_000_000_000).trust_me(),
                root: MsgAddressInt::from_str(
                    "0:34eefc8c8fb2b1e8da6fd6c86c1d5bcee1893bb81d34b3a085e301f2fba8d59c",
                )
                .trust_me(),
            },
        }
    }
}

fn load_secret_key(path: PathBuf) -> Result<(SecretKey, PublicKey)> {
    #[derive(serde::Deserialize)]
    struct Content {
        mnemonic: Option<String>,
        secret: Option<[u8; 32]>,
    }
    let data = std::fs::read_to_string(path).context("Failed to load keys")?;
    let Content { secret, mnemonic } = serde_json::from_str(&data).context("Invalid keys")?;
    match (mnemonic, secret) {
        (None, None) => {
            bail!("Neither mnemonic nor secret were provided")
        }
        (Some(_), Some(_)) => {
            bail!("Both mnemonic and secret were provided")
        }
        (None, Some(s)) => {
            let sk = SecretKey::from_bytes(s.as_ref())?;
            let public = PublicKey::from(&sk);
            Ok((sk, public))
        }
        (Some(seed), None) => {
            let keypair = derive_from_phrase(&seed, nekoton::crypto::MnemonicType::Labs(0))?;
            Ok((keypair.secret, keypair.public))
        }
    }
}

fn prepare_ever_wallet_transfer(
    pubkey: PublicKey,
    address: MsgAddressInt,
    amount: u64,
    destination: MsgAddressInt,
    contract: ExistingContract,
    body: Option<SliceData>,
) -> anyhow::Result<(ton_types::Cell, Box<dyn UnsignedMessage>)> {
    let gift = Gift {
        flags: 3,
        bounce: true,
        destination,
        amount,
        body,
        state_init: None,
    };
    let expiration = Expiration::Timeout(DEFAULT_EXPIRATION_TIMEOUT);

    let action = nekoton::core::ton_wallet::ever_wallet::prepare_transfer(
        &SimpleClock,
        &pubkey,
        &contract.account,
        address,
        vec![gift],
        expiration,
    )?;

    let unsigned_message = match action {
        TransferAction::Sign(message) => message,
        TransferAction::DeployFirst => {
            bail!("EverWallet unreachable action")
        }
    };

    // Sign with null signature to extract payload later
    let signed_message = unsigned_message.sign(&[0_u8; 64])?;
    let mut data = signed_message.message.body().trust_me();

    let first_bit = data.get_next_bit()?;
    assert!(first_bit);

    // Skip null signature
    data.move_by(SIGNATURE_LENGTH * 8)?;

    let payload = data.into_cell();

    Ok((payload, unsigned_message))
}

fn prepare_token_body(
    tokens: BigUint,
    owner: &MsgAddressInt,
    destination: &MsgAddressInt,
    notify: bool,
    payload: ton_types::Cell,
) -> anyhow::Result<SliceData> {
    let (function_token, input_token) =
        MessageBuilder::new(tip3_1::token_wallet_contract::transfer())
            .arg(BigUint128(tokens)) // amount
            .arg(destination) // recipient owner wallet
            .arg(BigUint128(INITIAL_BALANCE.into())) // deployWalletValue
            .arg(owner) // remainingGasTo
            .arg(notify) // notify
            .arg(payload) // payload
            .build();

    SliceData::load_builder(function_token.encode_internal_input(&input_token)?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let htlc_address = MsgAddressInt::from_str(
        "0:f14283332068aa65506654caaf2afadf73c480c395121974ae77b73fa77fabec", // "now" contract with fixed tests

                                                                              //"0:715729daf52135ec21387bfb260a49ec29294ae8fe85b84352fe17626373a624",
                                                                              //"0:1e55eb7e67a21c782a43191f4f80702dbc09ac2a2aec734671e6bdfd49bbdf59", // All checks
                                                                              // "0:6c3ddbac7c1bace04107829d097921c77c25dcab62da364ed321c357a351a09d", // Internal Owner
                                                                              // ExternalOwner
                                                                              //"0:b0ddef39702420236bb8ba8baa361006f9e43a5b7075d15e4d9a2d6abd0d07d8", // no payload size check
                                                                              //"0:80c0247aee276433bcd79e560c8b16cf781ead978f2bfdbcbb21e2bc87c81f9f", // payload check
                                                                              //wrong token roots all of them
                                                                              //"0:68d9b79433aa20345128ac57477a8f7a42eb3a7999803ab06b41038f6cbdeb1d", // return logic
                                                                              //"0:ffc6be253c09efbbe2daea5ef5a415052c5c2f52ba6f7613361dfa8ad8884148",
                                                                              //"0:6a873a1838d3e09603b8cb68d238e376f58fa492573a709bee65c53c581a9fb1",
                                                                              //"0:7d47582efa04de551018ac22b0177f4523a47a54cd0eabf3ea291208970944a7",
    )?;

    let args = Args::parse();

    if !args.keystore.exists() {
        println!("No key file was found. Generating new keys");

        let secret = SecretKey::generate(&mut rand::thread_rng());
        let public = PublicKey::from(&secret);

        let json = serde_json::json!({
            "secret": hex::encode(secret.as_bytes()),
            "public": hex::encode(public.as_bytes()),
        });

        let json_str = serde_json::to_string_pretty(&json).expect("Shouldn't fail");
        //println!("{}",json_str);

        // Create and write to the file
        let mut file = File::create(args.keystore.clone()).expect("Failed to create file");
        file.write_all(json_str.as_bytes())
            .expect("Failed to write to file");

        println!("JSON written to {}", args.keystore.display());
    }

    let (sk, pubkey) = load_secret_key(args.keystore)?;

    match args.command {
        SubCommand::GetPubkey => {
            println!("Public key: 0x{}", hex::encode(pubkey.to_bytes()));
        }
        SubCommand::GetAddress { wallet } => {
            let wtype = WalletType::from_str(&wallet).map_err(|s| anyhow::anyhow!(s))?;
            let address = compute_address(&pubkey, wtype, 0);
            println!("Address: {}", address);
        }
        SubCommand::GetBalance { wallet } => {
            let wtype = WalletType::from_str(&wallet).map_err(|s| anyhow::anyhow!(s))?;

            let address = compute_address(&pubkey, wtype, 0);

            let client = everscale_rpc_client::RpcClient::new(
                vec![Url::parse(RPC_ENDPOINT)?],
                everscale_rpc_client::ClientOptions::default(),
            )
            .await?;

            let contract = client.get_contract_state(&address, None).await?;
            match contract {
                Some(contract) => {
                    let mut balance =
                        Decimal::from_u128(contract.account.storage.balance.grams.as_u128())
                            .trust_me();
                    balance.set_scale(9_u32)?;
                    println!("Balance: {} EVER", balance);
                }
                None => {
                    println!("Account haven't deployed yet");
                }
            }
        }
        SubCommand::SendTransaction {
            wallet,
            amount,
            address,
        } => {
            let amount = (Decimal::from_str(&amount)? * Decimal::from(1_000_000_000))
                .to_u64()
                .trust_me();
            let destination = MsgAddressInt::from_str(&address)?;

            let wtype = WalletType::from_str(&wallet).map_err(|s| anyhow::anyhow!(s))?;

            let address = compute_address(&pubkey, wtype, 0);

            let client = everscale_rpc_client::RpcClient::new(
                vec![Url::parse(RPC_ENDPOINT)?],
                everscale_rpc_client::ClientOptions::default(),
            )
            .await?;

            let contract = client.get_contract_state(&address, None).await?;
            match contract {
                Some(contract) => match wtype {
                    WalletType::EverWallet => {
                        let (payload, unsigned_message) = prepare_ever_wallet_transfer(
                            pubkey,
                            address.clone(),
                            amount,
                            destination,
                            contract,
                            None,
                        )?;

                        let _boc = ton_types::serialize_toc(&payload)?;

                        let _meta = SignTransactionMeta::default();

                        let keypair: Keypair = Keypair {
                            secret: sk,
                            public: pubkey,
                        };

                        let signature = keypair.sign(unsigned_message.hash());
                        let signed_message =
                            unsigned_message.sign(&nekoton::crypto::Signature::from(signature))?;

                        println!(
                            "Sending message with hash '{}'...",
                            signed_message.message.hash()?.to_hex_string()
                        );

                        let status = client
                            .send_message(
                                signed_message.message,
                                everscale_rpc_client::SendOptions::default(),
                            )
                            .await?;

                        println!("Send status: {:?}", status);
                    }
                    _ => unimplemented!(),
                },
                None => {
                    println!(
                        "Account state not found. You should send 1 EVER to {}",
                        address
                    );
                }
            }
        }
        SubCommand::GetTokenBalance {
            wallet,
            token,
            address,
        } => {
            let token_wallet = match address {
                None => {
                    let wtype = WalletType::from_str(&wallet).map_err(|s| anyhow::anyhow!(s))?;
                    compute_address(&pubkey, wtype, 0)
                }
                Some(a) => MsgAddressInt::from_str(&a)?,
            };

            let client = everscale_rpc_client::RpcClient::new(
                vec![Url::parse(RPC_ENDPOINT)?],
                everscale_rpc_client::ClientOptions::default(),
            )
            .await?;

            let contract = client.get_contract_state(&token_wallet, None).await?;
            match contract {
                Some(_) => {
                    let token: Token = Token::from_str(&token)?;
                    let token_details = token.details();

                    let root_contract = client
                        .get_contract_state(&token_details.root, None)
                        .await?
                        .trust_me();

                    let token_address = RootTokenContractState(&root_contract).get_wallet_address(
                        &SimpleClock,
                        TokenWalletVersion::Tip3,
                        &token_wallet,
                    )?;

                    let token_contract = client.get_contract_state(&token_address, None).await?;
                    match token_contract {
                        Some(token_contract) => {
                            let state = TokenWalletContractState(&token_contract);
                            let balance =
                                state.get_balance(&SimpleClock, TokenWalletVersion::Tip3)?;

                            println!(
                                "Balance: {} {}",
                                BigDecimal::new(
                                    balance.to_bigint().trust_me(),
                                    token_details.decimals as i64
                                ),
                                token_details.ticker
                            );
                        }
                        None => {
                            println!("Token account haven't deployed yet");
                        }
                    }
                }
                None => {
                    println!("Account haven't deployed yet");
                }
            }
        }
        SubCommand::SendTokenTransaction {
            wallet,
            amount,
            address,
            token,
        } => {
            let token: Token = Token::from_str(&token)?;
            let token_details = token.details();

            let amount = (BigDecimal::from_str(&amount)? * token_details.factor)
                .with_scale(0)
                .into_bigint_and_exponent()
                .0
                .to_biguint()
                .trust_me();

            let destination = MsgAddressInt::from_str(&address)?;

            let wtype = WalletType::from_str(&wallet).map_err(|s| anyhow::anyhow!(s))?;

            let owner = compute_address(&pubkey, wtype, 0);

            let client = everscale_rpc_client::RpcClient::new(
                vec![Url::parse(RPC_ENDPOINT)?],
                everscale_rpc_client::ClientOptions::default(),
            )
            .await?;

            let owner_contract = client.get_contract_state(&owner, None).await?;
            match owner_contract {
                Some(owner_contract) => {
                    let root_contract = client
                        .get_contract_state(&token_details.root, None)
                        .await?
                        .trust_me();
                    let owner_token = RootTokenContractState(&root_contract).get_wallet_address(
                        &SimpleClock,
                        TokenWalletVersion::Tip3,
                        &owner,
                    )?;

                    let payload: ton_types::Cell = Default::default();

                    let token_body =
                        prepare_token_body(amount, &owner, &destination, false, payload)?;

                    match wtype {
                        WalletType::EverWallet => {
                            let (payload, unsigned_message) = prepare_ever_wallet_transfer(
                                pubkey,
                                owner,
                                ATTACHED_AMOUNT,
                                owner_token,
                                owner_contract,
                                Some(token_body),
                            )?;

                            let _meta = SignTransactionMeta::default();

                            let _boc = ton_types::serialize_toc(&payload)?;

                            let keypair: Keypair = Keypair {
                                secret: sk,
                                public: pubkey,
                            };

                            let signature = keypair.sign(unsigned_message.hash());
                            let signed_message = unsigned_message
                                .sign(&nekoton::crypto::Signature::from(signature))?;

                            println!(
                                "Sending message with hash '{}'...",
                                signed_message.message.hash()?.to_hex_string()
                            );

                            let status = client
                                .send_message(
                                    signed_message.message,
                                    everscale_rpc_client::SendOptions::default(),
                                )
                                .await?;

                            println!("Send status: {:?}", status);
                        }
                        _ => unimplemented!(),
                    }
                }
                None => {
                    println!(
                        "Account state not found. You should send 1 EVER to {}",
                        address
                    );
                }
            }
        }
        SubCommand::SendInboundHtlcTransaction {
            wallet,
            amount,
            counterparty,
            token,
            preimage,
            expire,
        } => {
            let token: Token = Token::from_str(&token)?;
            let token_details = token.details();

            let amount = (BigDecimal::from_str(&amount)? * token_details.factor)
                .with_scale(0)
                .into_bigint_and_exponent()
                .0
                .to_biguint()
                .trust_me();

            let destination = MsgAddressInt::from_str(&counterparty)?;

            let wtype = WalletType::from_str(&wallet).map_err(|s| anyhow::anyhow!(s))?;

            let owner = compute_address(&pubkey, wtype, 0);

            let client = everscale_rpc_client::RpcClient::new(
                vec![Url::parse(RPC_ENDPOINT)?],
                everscale_rpc_client::ClientOptions::default(),
            )
            .await?;

            let owner_contract = client.get_contract_state(&owner, None).await?;
            match owner_contract {
                Some(owner_contract) => {
                    let root_contract = client
                        .get_contract_state(&token_details.root, None)
                        .await?
                        .trust_me();

                    let owner_token = RootTokenContractState(&root_contract).get_wallet_address(
                        &SimpleClock,
                        TokenWalletVersion::Tip3,
                        &owner,
                    )?;

                    let _htlc_contract = client
                        .get_contract_state(&token_details.root, None)
                        .await?
                        .trust_me();

                    let input_preimage = match preimage {
                        Some(value) => value,
                        None => generate_random_hex(32), // Generating a 32-byte random hex string
                    };

                    let hashlock = match decode(input_preimage) {
                        Ok(sec_bytes) => {
                            if sec_bytes.len() == 32 {
                                compute_sha256(&sec_bytes)
                            } else {
                                bail!("Decoded bytes are not 32 bytes in length.");
                            }
                        }
                        Err(e) => bail!("Failed to decode hex: {}", e),
                    };

                    println!("SHA-256: {}", encode(hashlock));

                    let timelock = now_sec_u64() + expire;

                    println!("Timelock: {}", timelock.clone());

                    let htlc_request = crate::models::HTLCRoutingRequest {
                        incoming: true,
                        counterparty: destination,
                        hashlock: UInt256::from_slice(&hashlock),
                        timelock,
                    }
                    .pack();

                    let payload_cell = pack_into_cell(&htlc_request, DEFAULT_ABI_VERSION).unwrap();

                    let token_body =
                        prepare_token_body(amount, &owner, &htlc_address, true, payload_cell)?;

                    match wtype {
                        WalletType::EverWallet => {
                            let (payload, unsigned_message) = prepare_ever_wallet_transfer(
                                pubkey,
                                owner,
                                200_000_000, //ATTACHED_AMOUNT,
                                owner_token,
                                owner_contract,
                                Some(token_body),
                            )?;

                            let _meta = SignTransactionMeta::default();

                            let _boc = ton_types::serialize_toc(&payload)?;

                            let keypair: Keypair = Keypair {
                                secret: sk,
                                public: pubkey,
                            };

                            let signature = keypair.sign(unsigned_message.hash());
                            let signed_message = unsigned_message
                                .sign(&nekoton::crypto::Signature::from(signature))?;

                            println!(
                                "Sending message with hash '{}'...",
                                signed_message.message.hash()?.to_hex_string()
                            );

                            client.apply_message(&signed_message.message).await?;

                            let status = client
                                .send_message(
                                    signed_message.message,
                                    everscale_rpc_client::SendOptions::default(),
                                )
                                .await?;

                            println!("Send status: {:?}", status);
                        }
                        _ => unimplemented!(),
                    }
                }
                None => {
                    println!(
                        "Account state not found. You should send 1 EVER to {}",
                        counterparty
                    );
                }
            }
        }
        SubCommand::GetContractState { address } => {
            let client = everscale_rpc_client::RpcClient::new(
                vec![Url::parse(RPC_ENDPOINT)?],
                everscale_rpc_client::ClientOptions::default(),
            )
            .await?;
            let contract = MsgAddressInt::from_str(&address)?;
            let contract_state = client.get_contract_state(&contract, None).await?;
            match contract_state {
                Some(contract_state) => {
                    let forwarder_state =
                        htlc::HTLC(contract_state.as_context(&SimpleClock)).get_details()?;
                    println!("HTLC state:");
                    for t in forwarder_state {
                        println!("\t{}", t);
                    }
                }
                None => {
                    println!("Account state {} not found", address);
                }
            }
        }
        SubCommand::SendOutboundHtlcTransaction {
            amount: _,
            counterparty,
            token,
            hashlock,
            timelock,
        } => {
            let client = everscale_rpc_client::RpcClient::new(
                vec![Url::parse(RPC_ENDPOINT)?],
                everscale_rpc_client::ClientOptions::default(),
            )
            .await?;

            let contract_state = client.get_contract_state(&htlc_address, None).await?;

            match contract_state {
                Some(contract_state) => {
                    let wtype =
                        WalletType::from_str("EverWallet").map_err(|s| anyhow::anyhow!(s))?;

                    let owner = compute_address(&pubkey, wtype, 0);
                    let owner_contract = client.get_contract_state(&owner, None).await?.unwrap();

                    let forwarder_state =
                        htlc::HTLC(contract_state.as_context(&SimpleClock)).get_details()?;

                    println!("HTLC state:");
                    for t in forwarder_state {
                        println!("\t{}", t);
                    }

                    let token: Token = Token::from_str(&token)?;
                    let _token_details = token.details();
                    /*
                    let amount = (BigDecimal::from_str(&amount)? * token_details.factor)
                        .with_scale(0)
                        .into_bigint_and_exponent()
                        .0
                        .to_biguint()
                        .trust_me();
                    */
                    let amount = 1_000_000_u128;

                    let destination = MsgAddressInt::from_str(&counterparty)?;

                    let hashlock_input = match hashlock {
                        None => {
                            let preimage = generate_random_hex(32);
                            println!("Preimage: {}", preimage);
                            let sec_bytes = decode(preimage)?;
                            let hash_bytes = compute_sha256(&sec_bytes);
                            UInt256::from_slice(&hash_bytes)
                        }
                        Some(h) => UInt256::from_str(h.as_str())?,
                    };

                    println!("SHA-256: {}", encode(hashlock_input));

                    let (function_token, input_token) =
                        MessageBuilder::new(htlc_forwarder_contract::route())
                            .arg(destination.clone())
                            .arg(amount)
                            .arg(hashlock_input)
                            .arg(timelock)
                            .build();

                    let body = SliceData::load_builder(
                        function_token
                            .encode_internal_input(&input_token)
                            .with_context(|| {
                                format!(
                                    "Failed to encode_internal_input of function: {:?}",
                                    function_token
                                )
                            })?,
                    )?;

                    let expiration = Expiration::Timeout(DEFAULT_EXPIRATION_TIMEOUT);

                    let action = nekoton::core::ton_wallet::ever_wallet::prepare_transfer(
                        &SimpleClock,
                        &pubkey,
                        &owner_contract.account,
                        owner,
                        vec![Gift {
                            flags: 3,
                            bounce: true,
                            destination: htlc_address.clone(),
                            amount: ATTACHED_AMOUNT,
                            body: Some(body),
                            state_init: None,
                        }],
                        expiration,
                    )?;

                    let unsigned_message = match action {
                        TransferAction::Sign(message) => message,
                        TransferAction::DeployFirst => {
                            bail!("EverWallet unreachable action")
                        }
                    };

                    let keypair: Keypair = Keypair {
                        secret: sk,
                        public: pubkey,
                    };

                    let data_to_sign =
                        ton_abi::extend_signature_with_id(unsigned_message.hash(), None);
                    let signature = keypair.sign(&data_to_sign).to_bytes();
                    let signed_message = unsigned_message
                        .sign(&signature)
                        .expect("invalid signature");
                    let message = signed_message.message;

                    println!("Sending message '{:?}'...", message.clone());

                    println!(
                        "Sending message with hash '{}'...",
                        message.hash()?.to_hex_string()
                    );

                    if let Err(e) = client.apply_message(&message).await {
                        log::error!("Error on apply message - {}", e.to_string());
                        return Err(e);
                    }

                    let status = client
                        .send_message(message, everscale_rpc_client::SendOptions::default())
                        .await?;

                    println!("Send status: {:?}", status);
                }
                None => {
                    println!("Account state {} not found", htlc_address);
                }
            }
        }
        SubCommand::SettleHtlc { preimage } => {
            let client = everscale_rpc_client::RpcClient::new(
                vec![Url::parse(RPC_ENDPOINT)?],
                everscale_rpc_client::ClientOptions::default(),
            )
            .await?;

            let contract_state = client.get_contract_state(&htlc_address, None).await?;

            match contract_state {
                Some(contract_state) => {
                    let wtype =
                        WalletType::from_str("EverWallet").map_err(|s| anyhow::anyhow!(s))?;

                    let owner = compute_address(&pubkey, wtype, 0);
                    let owner_contract = client.get_contract_state(&owner, None).await?.unwrap();

                    let forwarder_state =
                        htlc::HTLC(contract_state.as_context(&SimpleClock)).get_details()?;

                    println!("HTLC state:");
                    for t in forwarder_state {
                        println!("\t{}", t);
                    }

                    let preimage_uint = UInt256::from_str(preimage.as_str())?;

                    let (function_token, input_token) =
                        MessageBuilder::new(htlc_forwarder_contract::settle())
                            .arg(preimage_uint)
                            .build();

                    let body = SliceData::load_builder(
                        function_token
                            .encode_internal_input(&input_token)
                            .with_context(|| {
                                format!(
                                    "Failed to encode_internal_input of function: {:?}",
                                    function_token
                                )
                            })?,
                    )?;

                    let expiration = Expiration::Timeout(DEFAULT_EXPIRATION_TIMEOUT);

                    let action = nekoton::core::ton_wallet::ever_wallet::prepare_transfer(
                        &SimpleClock,
                        &pubkey,
                        &owner_contract.account,
                        owner,
                        vec![Gift {
                            flags: 3,
                            bounce: true,
                            destination: htlc_address.clone(),
                            amount: ATTACHED_AMOUNT,
                            body: Some(body),
                            state_init: None,
                        }],
                        expiration,
                    )?;

                    let unsigned_message = match action {
                        TransferAction::Sign(message) => message,
                        TransferAction::DeployFirst => {
                            bail!("EverWallet unreachable action")
                        }
                    };

                    let keypair: Keypair = Keypair {
                        secret: sk,
                        public: pubkey,
                    };

                    let data_to_sign =
                        ton_abi::extend_signature_with_id(unsigned_message.hash(), None);
                    let signature = keypair.sign(&data_to_sign).to_bytes();
                    let signed_message = unsigned_message
                        .sign(&signature)
                        .expect("invalid signature");
                    let message = signed_message.message;

                    println!(
                        "Sending message with hash '{}'...",
                        message.hash()?.to_hex_string()
                    );

                    if let Err(e) = client.apply_message(&message).await {
                        log::error!("Error on apply message - {}", e.to_string());
                        return Err(e);
                    }

                    let status = client
                        .send_message(message, everscale_rpc_client::SendOptions::default())
                        .await?;

                    println!("Send status: {:?}", status);
                }
                None => {
                    println!("Account state {} not found", htlc_address);
                }
            }
        }
        SubCommand::RefundHtlc => {
            let client = everscale_rpc_client::RpcClient::new(
                vec![Url::parse(RPC_ENDPOINT)?],
                everscale_rpc_client::ClientOptions::default(),
            )
            .await?;

            let contract_state = client.get_contract_state(&htlc_address, None).await?;

            match contract_state {
                Some(contract_state) => {
                    let wtype =
                        WalletType::from_str("EverWallet").map_err(|s| anyhow::anyhow!(s))?;

                    let owner = compute_address(&pubkey, wtype, 0);
                    let owner_contract = client.get_contract_state(&owner, None).await?.unwrap();

                    let forwarder_state =
                        htlc::HTLC(contract_state.as_context(&SimpleClock)).get_details()?;

                    println!("HTLC state:");
                    for t in forwarder_state {
                        println!("\t{}", t);
                    }

                    let (function_token, input_token) =
                        MessageBuilder::new(htlc_forwarder_contract::refund()).build();

                    let body = SliceData::load_builder(
                        function_token
                            .encode_internal_input(&input_token)
                            .with_context(|| {
                                format!(
                                    "Failed to encode_internal_input of function: {:?}",
                                    function_token
                                )
                            })?,
                    )?;

                    let expiration = Expiration::Timeout(DEFAULT_EXPIRATION_TIMEOUT);

                    let action = nekoton::core::ton_wallet::ever_wallet::prepare_transfer(
                        &SimpleClock,
                        &pubkey,
                        &owner_contract.account,
                        owner,
                        vec![Gift {
                            flags: 3,
                            bounce: true,
                            destination: htlc_address.clone(),
                            amount: ATTACHED_AMOUNT,
                            body: Some(body),
                            state_init: None,
                        }],
                        expiration,
                    )?;

                    let unsigned_message = match action {
                        TransferAction::Sign(message) => message,
                        TransferAction::DeployFirst => {
                            bail!("EverWallet unreachable action")
                        }
                    };

                    let keypair: Keypair = Keypair {
                        secret: sk,
                        public: pubkey,
                    };

                    let data_to_sign =
                        ton_abi::extend_signature_with_id(unsigned_message.hash(), None);
                    let signature = keypair.sign(&data_to_sign).to_bytes();
                    let signed_message = unsigned_message
                        .sign(&signature)
                        .expect("invalid signature");
                    let message = signed_message.message;

                    println!(
                        "Sending message with hash '{}'...",
                        message.hash()?.to_hex_string()
                    );

                    if let Err(e) = client.apply_message(&message).await {
                        log::error!("Error on apply message - {}", e.to_string());
                        return Err(e);
                    }

                    let status = client
                        .send_message(message, everscale_rpc_client::SendOptions::default())
                        .await?;

                    println!("Send status: {:?}", status);
                }
                None => {
                    println!("Account state {} not found", htlc_address);
                }
            }
        }
        SubCommand::GetWallets => {
            println!(
                "WalletV3\nEverWallet\nSafeMultisig\nSafeMultisig24h\nSetcodeMultisig\nBridgeMultisig\nMultisig2\nMultisig2_1\nSurf (unimplemented)",
            );
        }
        SubCommand::GetTokens => {
            println!("WEVER\nUSDT\nUSDC\nDAI",);
        }
        SubCommand::Deploy { wallet } => {
            let wtype = WalletType::from_str(&wallet).map_err(|s| anyhow::anyhow!(s))?;

            let address = compute_address(&pubkey, wtype, 0);

            let client = everscale_rpc_client::RpcClient::new(
                vec![Url::parse(RPC_ENDPOINT)?],
                everscale_rpc_client::ClientOptions::default(),
            )
            .await?;

            let contract = client.get_contract_state(&address, None).await?;
            match contract {
                Some(_contract) => match wtype {
                    WalletType::WalletV3 | WalletType::EverWallet => {
                        println!("No need to deploy");
                    }
                    _ => unimplemented!(),
                },
                None => {
                    println!(
                        "Account state not found. You should send 1 EVER to {}",
                        address
                    );
                }
            }
        }
    };

    Ok(())
}

#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
pub struct SignTransactionMeta {
    chain_id: Option<u32>,
    workchain_id: Option<u8>,
    current_wallet_type: Option<WalletType>,
}

impl SignTransactionMeta {
    pub fn new(
        chain_id: Option<u32>,
        workchain_id: Option<u8>,
        current_wallet_type: Option<WalletType>,
    ) -> Self {
        Self {
            chain_id,
            workchain_id,
            current_wallet_type,
        }
    }
}

fn generate_random_hex(length: usize) -> String {
    let random_bytes: Vec<u8> = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .collect();

    encode(random_bytes)
}

fn compute_sha256(data: &[u8]) -> Output<Sha256> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/*
Usage:

                    let state = match client.get_contract_state(&htlc_address, None).await? {
                        Some(ec) => ec,
                        None => bail!("No HTLC contract found")
                    };


                    let expiration = Expiration::Timeout(DEFAULT_EXPIRATION_TIMEOUT);
                    let action = prepare_routing(
                        &SimpleClock,
                        &pubkey,
                        &state.account,
                        htlc_address.clone(),
                        destination,
                        amount,
                        hashlock_input,
                        timelock,
                        vec![],
                        expiration,
                    )?;


pub fn prepare_routing(
    clock: &dyn Clock,
    public_key: &PublicKey,
    current_state: &ton_block::AccountStuff,
    address: MsgAddressInt,
    counterparty: MsgAddressInt,
    amount: u128,
    hashlock: UInt256,
    timelock: u64,
    gifts: Vec<Gift>,
    expiration: Expiration,
) -> Result<TransferAction> {
    use nekoton_contracts::wallets::ever_wallet;

    if gifts.len() > 4 {
        return bail!("gifts.len() > MAX_MESSAGES");
    }

    let mut message =
        ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
            dst: address,
            ..Default::default()
        });

    match &current_state.storage.state {
        ton_block::AccountState::AccountActive { .. } => {}
        ton_block::AccountState::AccountFrozen { .. } => {
            return bail!("AccountFrozen");
        }
        ton_block::AccountState::AccountUninit => {
            return bail!("AccountUninit");
        }
    };

    let mut gifts = gifts.into_iter();
    let (function, input) = match (gifts.len(), gifts.next()) {
        (1, Some(gift)) if gift.state_init.is_none() => {
                MessageBuilder::new(htlc_forwarder_contract::route())
                    .arg(counterparty.clone())
                    .arg(amount.clone())
                    .arg(hashlock.clone())
                    .arg(timelock.clone())
                    .build()
        }
        (len, gift) => {
            let function = match len {
                0 => ever_wallet::send_transaction_raw_0(),
                1 => ever_wallet::send_transaction_raw_1(),
                2 => ever_wallet::send_transaction_raw_2(),
                3 => ever_wallet::send_transaction_raw_3(),
                _ => ever_wallet::send_transaction_raw_4(),
            };

            let mut tokens = Vec::with_capacity(len * 2);
            for gift in gift.into_iter().chain(gifts) {
                let mut internal_message =
                    ton_block::Message::with_int_header(ton_block::InternalMessageHeader {
                        ihr_disabled: true,
                        bounce: gift.bounce,
                        dst: gift.destination,
                        value: gift.amount.into(),
                        ..Default::default()
                    });

                if let Some(body) = gift.body {
                    internal_message.set_body(body);
                }

                if let Some(state_init) = gift.state_init {
                    internal_message.set_state_init(state_init);
                }

                tokens.push(ton_abi::Token::new("flags", gift.flags.token_value()));
                tokens.push(ton_abi::Token::new(
                    "message",
                    internal_message.serialize()?.token_value(),
                ));
            }

            (function, tokens)
        }
    };

    Ok(TransferAction::Sign(make_labs_unsigned_message(
        clock,
        message,
        expiration,
        public_key,
        Cow::Borrowed(function),
        input,
    )?))
}
*/

// TODO: zone
// Payload test
//println!("{}", payload.clone());
//println!("{:?}", payload.clone());
//bail!("no panic");
//const BOC: &str = "te6ccgEBAQEATAAAk8AFOkpSe4NBB2OYjrhiVa7JbBVXaWi+R/PycKStT4HWcxfRoAh+ST/3cvc3fpUpidy94xfKDpWs9oqTWWvQQLqI8AAAAAAAAAAY";
//let boc = create_boc_or_comment_payload(BOC).unwrap().into_cell();
//let target_boc =
//    ton_types::deserialize_tree_of_cells(&mut base64::decode(BOC).unwrap().as_slice())
//        .unwrap();
//HTLC state:
//    incoming : true
//counterparty : 0:53a4a527b83410763988eb86255aec96c15576968be47f3f270a4ad4f81d6731
//tokenRoot : 0:34eefc8c8fb2b1e8da6fd6c86c1d5bcee1893bb81d34b3a085e301f2fba8d59c
//tokenWallet : 0:9dbc4e95dd63a5bb2dbdee7a083afadf181452722bf62ec4fcdcebee32794c87
//amount : 10000000000000
//hashlock : 56585047760257421914823539804167948508530566294874898018863863747136530917519
//timelock : 1
//capacity : 10000000000000
//[ilya@fedora everscale-con-wallet]$ ./target/debug/client --keystore keys.json send-htlc-transaction --amount=1 --counterparty=0:82d6884271fab6516973024db8247c807f56085c99526d965d4bae695885f969 --token=SAT
//Hash: 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969
//bits: 588
