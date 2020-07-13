extern crate serde_derive;
extern crate ethstore_lib;
extern crate ethstore;

use std::collections::VecDeque;
use std::io::Read;
use std::{env, process, fs, fmt};

use structopt::StructOpt;
use ethereum_types::{H160, H256, U256};
use std::collections::BTreeMap;
use std::str::FromStr;

use ethstore_lib::ethstore_rely::*;
use ethstore_lib::crack;
use docopt::Docopt;
use ethstore::{EthStore, SimpleSecretStore, SecretStore, import_accounts, PresaleWallet, SecretVaultRef, StoreAccountRef};


// target/debug/bloom-cmd ethstore insert 7d29fab185a33e2cd955812397354c472d2b84615b645aa135ff539f6b0d70d5 password.txt
// target/debug/bloom-cmd ethstore change-pwd a8fa5dd30a87bb9e3288d604eb74949c515ab66e old_pwd.txt new_pwd.txt
// target/debug/bloom-cmd ethstore list

fn execute<S, I>(command: I) -> Result<String, Error> where I: IntoIterator<Item=S>, S: AsRef<str> {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.argv(command).deserialize())?;

    let store = EthStore::open(key_dir(&args.flag_dir, None)?)?;

    return if args.cmd_insert {
        let secret = args.arg_secret.parse().map_err(|_| ethstore::Error::InvalidSecret)?;
        let password = load_password(&args.arg_password)?;
        let vault_ref = open_args_vault(&store, &args)?;
        let account_ref = store.insert_account(vault_ref, secret, &password)?;
        Ok(format!("0x{:x}", account_ref.address))
    }else if args.cmd_change_pwd {
        let address = args.arg_address.parse().map_err(|_| ethstore::Error::InvalidAccount)?;
        let old_pwd = load_password(&args.arg_old_pwd)?;
        let new_pwd = load_password(&args.arg_new_pwd)?;
        let account_ref = open_args_vault_account(&store, address, &args)?;
        let ok = store.change_password(&account_ref, &old_pwd, &new_pwd).is_ok();
        Ok(format!("{}", ok))
    } else if args.cmd_list {
        let vault_ref = open_args_vault(&store, &args)?;
        let accounts = store.accounts()?;
        let accounts: Vec<_> = accounts
            .into_iter()
            .filter(|a| &a.vault == &vault_ref)
            .map(|a| a.address)
            .collect();
        Ok(format_accounts(&accounts))
    } else if args.cmd_import {
        let password = match args.arg_password.as_ref() {
            "" => None,
            _ => Some(load_password(&args.arg_password)?)
        };
        let src = key_dir(&args.flag_src, password)?;
        let dst = key_dir(&args.flag_dir, None)?;

        let accounts = import_accounts(&*src, &*dst)?;
        Ok(format_accounts(&accounts))
    } else if args.cmd_import_wallet {
        let wallet = PresaleWallet::open(&args.arg_path)?;
        let password = load_password(&args.arg_password)?;
        let kp = wallet.decrypt(&password)?;
        let vault_ref = open_args_vault(&store, &args)?;
        let account_ref = store.insert_account(vault_ref, kp.secret().clone(), &password)?;
        Ok(format!("0x{:x}", account_ref.address))
    } else if args.cmd_find_wallet_pass {
        let passwords = load_password(&args.arg_password)?;
        let passwords = passwords.as_str().lines().map(|line| str::to_owned(line).into()).collect::<VecDeque<_>>();
        crack::run(passwords, &args.arg_path)?;
        Ok(format!("Password not found."))
    } else if args.cmd_remove {
        let address = args.arg_address.parse().map_err(|_| ethstore::Error::InvalidAccount)?;
        let password = load_password(&args.arg_password)?;
        let account_ref = open_args_vault_account(&store, address, &args)?;
        let ok = store.remove_account(&account_ref, &password).is_ok();
        Ok(format!("{}", ok))
    } else if args.cmd_sign {
        let address = args.arg_address.parse().map_err(|_| ethstore::Error::InvalidAccount)?;
        let message = args.arg_message.parse().map_err(|_| ethstore::Error::InvalidMessage)?;
        let password = load_password(&args.arg_password)?;
        let account_ref = open_args_vault_account(&store, address, &args)?;
        let signature = store.sign(&account_ref, &password, &message)?;
        Ok(format!("0x{}", signature))
    } else if args.cmd_public {
        let address = args.arg_address.parse().map_err(|_| ethstore::Error::InvalidAccount)?;
        let password = load_password(&args.arg_password)?;
        let account_ref = open_args_vault_account(&store, address, &args)?;
        let public = store.public(&account_ref, &password)?;
        Ok(format!("0x{:x}", public))
    } else if args.cmd_list_vaults {
        let vaults = store.list_vaults()?;
        Ok(format_vaults(&vaults))
    } else if args.cmd_create_vault {
        let password = load_password(&args.arg_password)?;
        store.create_vault(&args.arg_vault, &password)?;
        Ok("OK".to_owned())
    } else if args.cmd_change_vault_pwd {
        let old_pwd = load_password(&args.arg_old_pwd)?;
        let new_pwd = load_password(&args.arg_new_pwd)?;
        store.open_vault(&args.arg_vault, &old_pwd)?;
        store.change_vault_password(&args.arg_vault, &new_pwd)?;
        Ok("OK".to_owned())
    } else if args.cmd_move_to_vault {
        let address = args.arg_address.parse().map_err(|_| ethstore::Error::InvalidAccount)?;
        let password = load_password(&args.arg_password)?;
        let account_ref = open_args_vault_account(&store, address, &args)?;
        store.open_vault(&args.arg_vault, &password)?;
        store.change_account_vault(SecretVaultRef::Vault(args.arg_vault), account_ref)?;
        Ok("OK".to_owned())
    } else if args.cmd_move_from_vault {
        let address = args.arg_address.parse().map_err(|_| ethstore::Error::InvalidAccount)?;
        let password = load_password(&args.arg_password)?;
        store.open_vault(&args.arg_vault, &password)?;
        store.change_account_vault(SecretVaultRef::Root, StoreAccountRef::vault(&args.arg_vault, address))?;
        Ok("OK".to_owned())
    } else {
        Ok(format!("{}", USAGE))
    }
}

#[derive(Debug, StructOpt, Clone)]
pub struct EthstoreCmd {
    #[structopt(subcommand)]
    cmd: Command
}

#[derive(StructOpt, Debug, Clone)]
enum Command {
    Insert{
        secret:String,
        password :String,
    },
    Change_pwd{
        address:String,
        old_pwd:String,
        new_pwd:String,
    },
    List{},
    Import{},
    Import_wallet{
        path:String,
        password:String,
    },
    Find_wallet_pass{
        path:String,
        password:String,
    },
    Remove{
        address:String,
        password:String,
    },
    Sign{
        address:String,
        password:String,
        message:String,
    },
    Public{
        address:String,
        password:String,
    },
    List_vaults{},
    Create_vault{
        vault:String,
        password:String,
    },
    Change_vault_pwd{
        vault:String,
        old_pwd:String,
        new_pwd:String,
    },
    Move_to_vault{
        address:String,
        vault:String,
        password:String,
    },
    Move_from_vault{
        address:String,
        vault:String,
        password:String,
    },
}

impl EthstoreCmd {
    pub fn run(&self, mut backend: &str) {
        match &self.cmd {
            Command::Insert { secret, password } => {
                println!("Query {:#?}", backend);
                let command = vec!["ethstore", "insert", secret, password]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result = execute(command).unwrap();
                println!("{}", result);
            },
            Command::Change_pwd {address,old_pwd,new_pwd} => {
                println!("Change-pwd {:#?}", backend);
                let command = vec!["ethstore","change-pwd",address, old_pwd, new_pwd]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result = execute(command).unwrap();
                println!("{}",result);
            },
            Command::List {} => {
                println!("List {:#?}", backend);
                let command = vec!["ethstore","list"]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result = execute(command).unwrap();
                println!("{}",result);
            },
            Command::Import {} => {
                println!("Import {:#?}", backend);
                let command = vec!["ethstore","import"]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result = execute(command).unwrap();
                println!("{}",result);
            },
            Command::Import_wallet {path,password} => {
                println!("Import_wallet {:#?}", backend);
                let command = vec!["ethstore","import-wallet", path, password]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result = execute(command).unwrap();
                println!("{}",result);
            },
            Command::Find_wallet_pass {path,password} => {
                println!("Find_wallet_pass {:#?}", backend);
                let command = vec!["ethstore","find-wallet-pass", path, password]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result = execute(command).unwrap();
                println!("{}",result);
            },
            Command::Remove {address, password} => {
                println!("Remove {:#?}", backend);
                let command = vec!["ethstore","remove", address, password]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result = execute(command).unwrap();
                println!("{}",result);
            },
            Command::Sign {address,password,message} => {
                println!("Sign {:#?}", backend);
                let command = vec!["ethstore","sign", address, password, message]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result = execute(command).unwrap();
                println!("{}",result);
            },
            Command::Public {address, password} => {
                println!("Public {:#?}", backend);
                let command = vec!["ethstore","public", address, password]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result = execute(command).unwrap();
                println!("{}",result);
            },
            Command::List_vaults {} => {
                println!("List_vaults {:#?}", backend);
                let command = vec!["ethstore","list-vaults"]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result = execute(command).unwrap();
                println!("{}",result);
            },
            Command::Create_vault {vault,password} => {
                println!("Create_vault {:#?}", backend);
                let command = vec!["ethstore","create-vault", vault, password]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result = execute(command).unwrap();
                println!("{}",result);
            },
            Command::Change_vault_pwd {vault,old_pwd,new_pwd} => {
                println!("Change_vault_pwd {:#?}", backend);
                let command = vec!["ethstore","change-vault-pwd", vault, old_pwd, new_pwd]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result = execute(command).unwrap();
                println!("{}",result);
            },
            Command::Move_to_vault {address, vault, password} => {
                println!("Move_to_vault {:#?}", backend);
                let command = vec!["ethstore","move-to-vault", address, vault, password]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result = execute(command).unwrap();
                println!("{}",result);
            },
            Command::Move_from_vault {address, vault, password} => {
                println!("Move_from_vault {:#?}", backend);
                let command = vec!["ethstore","move-from-vault", address, vault, password]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result = execute(command).unwrap();
                println!("{}",result);
            }
        }
    }
}

#[test]
fn test_insert() {
    let secret = "7d29fab185a33e2cd955812397354c472d2b84615b645aa135ff539f6b0d70d5";
    let password = "E:\\Code\\RustCode\\rpc-proxy-master\\cmd-ethstore-master\\target\\debug\\password.txt";

    let command = vec!["ethstore", "insert", secret, password]
        .into_iter()
        .map(Into::into)
        .collect::<Vec<String>>();
    let result = execute(command).unwrap();
    assert_eq!(result, "0xa8fa5dd30a87bb9e3288d604eb74949c515ab66e");
}



