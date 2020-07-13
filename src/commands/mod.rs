mod account_cmd;
mod contract_cmd;
mod ethstore_cmd;


use std::collections::BTreeMap;

use structopt::StructOpt;
use account_cmd::AccountCmd;
use contract_cmd::ContractCmd;
use ethstore_cmd::EthstoreCmd;

use ethereum_types::{U256, H160};

#[derive(Debug, Clone, StructOpt)]
pub enum Subcommand {
	Account(AccountCmd),
	Contract(ContractCmd),
	Ethstore(EthstoreCmd),
}

impl Subcommand {

	pub fn run(&self) {

		let backend = "some backend args";

		match self {
			Subcommand::Account(cmd) => {
				println!("##Subcommand: Account##");
				cmd.run(backend);
			}
			Subcommand::Contract(cmd) => {
				println!("##Subcommand: Contract##");
				cmd.run(backend);
			}
			Subcommand::Ethstore(cmd)=> {
				println!("##Subcommand: Ethstore##");
				cmd.run(backend);
			}
		}

	}

}
