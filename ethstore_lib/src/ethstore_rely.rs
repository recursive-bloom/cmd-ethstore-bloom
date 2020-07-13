extern crate dir;
extern crate docopt;
extern crate ethstore;
extern crate ethkey;
extern crate num_cpus;
extern crate panic_hook;
extern crate parking_lot;
extern crate parity_crypto;
extern crate rustc_hex;
extern crate serde;
extern crate env_logger;
extern crate serde_derive;

use std::collections::VecDeque;
use std::io::Read;
use std::{env, process, fs, fmt};
use serde::{Deserialize, Serialize};

use docopt::Docopt;
use ethstore::accounts_dir::{KeyDirectory, RootDiskDirectory};
use ethkey::Password;
use parity_crypto::publickey::Address;
use ethstore::{EthStore, SimpleSecretStore, SecretStore, import_accounts, PresaleWallet, SecretVaultRef, StoreAccountRef};


pub const USAGE: &'static str = r#"
OpenEthereum key management tool.
  Copyright 2015-2020 Parity Technologies (UK) Ltd.

Usage:
    ethstore insert <secret> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    ethstore change-pwd <address> <old-pwd> <new-pwd> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    ethstore list [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    ethstore import [<password>] [--src DIR] [--dir DIR]
    ethstore import-wallet <path> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    ethstore find-wallet-pass <path> <password>
    ethstore remove <address> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    ethstore sign <address> <password> <message> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    ethstore public <address> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    ethstore list-vaults [--dir DIR]
    ethstore create-vault <vault> <password> [--dir DIR]
    ethstore change-vault-pwd <vault> <old-pwd> <new-pwd> [--dir DIR]
    ethstore move-to-vault <address> <vault> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    ethstore move-from-vault <address> <vault> <password> [--dir DIR]
    ethstore [-h | --help]

Options:
    -h, --help               Display this message and exit.
    --dir DIR                Specify the secret store directory. It may be either
                             parity, parity-(chain), geth, geth-test
                             or a path [default: parity].
    --vault VAULT            Specify vault to use in this operation.
    --vault-pwd VAULTPWD     Specify vault password to use in this operation. Please note
                             that this option is required when vault option is set.
                             Otherwise it is ignored.
    --src DIR                Specify import source. It may be either
                             parity, parity-(chain), geth, geth-test
                             or a path [default: geth].

Commands:
    insert             Save account with password.
    change-pwd         Change password.
    list               List accounts.
    import             Import accounts from src.
    import-wallet      Import presale wallet.
    find-wallet-pass   Tries to open a wallet with list of passwords given.
    remove             Remove account.
    sign               Sign message.
    public             Displays public key for an address.
    list-vaults        List vaults.
    create-vault       Create new vault.
    change-vault-pwd   Change vault password.
    move-to-vault      Move account to vault from another vault/root directory.
    move-from-vault    Move account to root directory from given vault.
"#;

#[derive(Debug, Deserialize)]
pub struct Args {
    pub cmd_insert: bool,
    pub cmd_change_pwd: bool,
    pub cmd_list: bool,
    pub cmd_import: bool,
    pub cmd_import_wallet: bool,
    pub cmd_find_wallet_pass: bool,
    pub cmd_remove: bool,
    pub cmd_sign: bool,
    pub cmd_public: bool,
    pub cmd_list_vaults: bool,
    pub cmd_create_vault: bool,
    pub cmd_change_vault_pwd: bool,
    pub cmd_move_to_vault: bool,
    pub cmd_move_from_vault: bool,
    pub arg_secret: String,
    pub arg_password: String,
    pub arg_old_pwd: String,
    pub arg_new_pwd: String,
    pub arg_address: String,
    pub arg_message: String,
    pub arg_path: String,
    pub arg_vault: String,
    pub flag_src: String,
    pub flag_dir: String,
    pub flag_vault: String,
    pub flag_vault_pwd: String,
}

#[derive(Debug)]
pub enum Error {
    Ethstore(ethstore::Error),
    Docopt(docopt::Error),
}

impl From<ethstore::Error> for Error {
    fn from(err: ethstore::Error) -> Self {
        Error::Ethstore(err)
    }
}

impl From<docopt::Error> for Error {
    fn from(err: docopt::Error) -> Self {
        Error::Docopt(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Ethstore(ref err) => fmt::Display::fmt(err, f),
            Error::Docopt(ref err) => fmt::Display::fmt(err, f),
        }
    }
}

pub fn key_dir(location: &str, password: Option<Password>) -> Result<Box<dyn KeyDirectory>, Error> {
    let dir: RootDiskDirectory = match location {
        "geth" => RootDiskDirectory::create(dir::geth(false))?,
        "geth-test" => RootDiskDirectory::create(dir::geth(true))?,
        path if path.starts_with("parity") => {
            let chain = path.split('-').nth(1).unwrap_or("ethereum");
            let mut path = dir::default_data_pathbuf();
            path.push("keys");
            path.push(chain);
            RootDiskDirectory::create(path)?
        },
        path => RootDiskDirectory::create(path)?,
    };

    Ok(Box::new(dir.with_password(password)))
}

pub fn open_args_vault(store: &EthStore, args: &Args) -> Result<SecretVaultRef, Error> {
    if args.flag_vault.is_empty() {
        return Ok(SecretVaultRef::Root);
    }

    let vault_pwd = load_password(&args.flag_vault_pwd)?;
    store.open_vault(&args.flag_vault, &vault_pwd)?;
    Ok(SecretVaultRef::Vault(args.flag_vault.clone()))
}

pub fn open_args_vault_account(store: &EthStore, address: Address, args: &Args) -> Result<StoreAccountRef, Error> {
    match open_args_vault(store, args)? {
        SecretVaultRef::Root => Ok(StoreAccountRef::root(address)),
        SecretVaultRef::Vault(name) => Ok(StoreAccountRef::vault(&name, address)),
    }
}

pub fn format_accounts(accounts: &[Address]) -> String {
    accounts.iter()
        .enumerate()
        .map(|(i, a)| format!("{:2}: 0x{:x}", i, a))
        .collect::<Vec<String>>()
        .join("\n")
}

pub fn format_vaults(vaults: &[String]) -> String {
    vaults.join("\n")
}

pub fn load_password(path: &str) -> Result<Password, Error> {
    let mut file = fs::File::open(path).map_err(|e| ethstore::Error::Custom(format!("Error opening password file '{}': {}", path, e)))?;
    let mut password = String::new();
    file.read_to_string(&mut password).map_err(|e| ethstore::Error::Custom(format!("Error reading password file '{}': {}", path, e)))?;
    // drop EOF
    let _ = password.pop();
    Ok(password.into())
}