// This file is part of Darwinia.
//
// Copyright (C) 2018-2021 Darwinia Network
// SPDX-License-Identifier: GPL-3.0
//
// Darwinia is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Darwinia is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Darwinia. If not, see <https://www.gnu.org/licenses/>.

//! Prototype module for cross chain assets issuing.

#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

pub use ethabi::{Event, Log};

// --- alloc ---
use alloc::vec::Vec;
// --- crates ---
use ethereum_types::{Address as EthereumAddress, H160, H256, U256};
// --- github ---
use ethabi::{
	param_type::ParamType, token::Token, Bytes, Error, EventParam, Function, Param, RawLog,
	Result as AbiResult,
};

pub type Erc20Name = [u8; 32];
pub type Erc20Symbol = [u8; 32];

pub struct Abi;

impl Abi {
	fn unlock() -> Function {
		let inputs = vec![
			Param {
				name: "token".into(),
				kind: ParamType::Address,
			},
			Param {
				name: "recipient".into(),
				kind: ParamType::Address,
			},
			Param {
				name: "amount".into(),
				kind: ParamType::Uint(256),
			},
		];

		Function {
			name: "unlock".into(),
			inputs,
			outputs: vec![],
			constant: false,
		}
	}

	/// this Token UnLock Event comes from the outer chains
	/// @params token: source erc20 token address
	/// @params recipient: the receiver on darwinia of the asset
	/// @params amount: transfer amount of the token
	pub fn unlock_event() -> Event {
		Event {
			name: "MappingTokenBurned".into(),
			inputs: vec![
				EventParam {
					name: "token".into(),
					kind: ParamType::Address,
					indexed: true,
				},
                EventParam {
					name: "recipient".into(),
					kind: ParamType::Address,
					indexed: false,
				},
				EventParam {
					name: "amount".into(),
					kind: ParamType::Uint(256),
					indexed: false,
				},
			],
			anonymous: false,
		}
	}

	/// encode unlock function for erc20
	pub fn encode_cross_unlock(
		token: EthereumAddress,
		recipient: EthereumAddress,
		amount: U256,
	) -> AbiResult<Bytes> {
		let unlock = Self::unlock();
		unlock.encode_input(
			vec![
				Token::Address(token.into()),
				Token::Address(recipient.into()),
				Token::Uint(amount.into()),
			]
			.as_slice(),
		)
	}

	/// parse token register event
	pub fn parse_event(topics: Vec<H256>, data: Vec<u8>, eth_event: Event) -> AbiResult<Log> {
		let log = RawLog {
			topics: topics.into_iter().map(|t| -> H256 { t.into() }).collect(),
			data: data.clone(),
		};
		eth_event.parse_log(log)
	}
}

fn slice_to_bytes32(source: &[u8]) -> [u8; 32] {
    let slice: &[u8] = if source.len() > 32 {
        &source[..32]
    } else {
        &source[..]
    };

    let mut result: [u8; 32] = Default::default();
    result[..slice.len()].clone_from_slice(slice);
    result
}


/// token register info
/// this is the darwinia token register info
/// and would be sent to the outer chain
/// (token, name, symbol, decimals)
#[derive(Debug, PartialEq, Eq)]
pub struct TokenRegisterInfo(pub H160, pub Erc20Name, pub Erc20Symbol, pub U256);

impl TokenRegisterInfo {
	pub fn decode(data: &[u8]) -> AbiResult<Self> {
		let tokens = ethabi::decode(
			&[ParamType::FixedBytes(4), ParamType::Address, ParamType::String, ParamType::String, ParamType::Uint(256)],
			&data,
		)?;
		match (tokens[0].clone(), tokens[1].clone(), tokens[2].clone(), tokens[3].clone(), tokens[4].clone()) {
			(Token::FixedBytes(_sig), Token::Address(token), Token::String(name), Token::String(symbol), Token::Uint(decimals)) => {
                let name = slice_to_bytes32(name.as_bytes());
                let symbol = slice_to_bytes32(symbol.as_bytes());
				Ok(TokenRegisterInfo(token, name, symbol, decimals))
			}
			_ => Err(Error::InvalidData),
		}
	}
}

/// token lock info
/// using darwinia backing contract to lock darwinia token
/// @chain_id: the target chain logic ID
/// @token: the source token address
/// @recipient: the final receiver of the token to be redeemed on the target chain
/// @amount: the amount of the locked token
#[derive(Debug, PartialEq, Eq)]
pub struct TokenLockedInfo {
	pub chain_id: U256,
	pub token: H160,
	pub recipient: H160,
	pub amount: U256,
}

impl TokenLockedInfo {
	pub fn decode(data: &[u8]) -> AbiResult<Self> {
		let tokens = ethabi::decode(
			&[
                ParamType::FixedBytes(4),
				ParamType::Uint(256),
				ParamType::Address,
				ParamType::Address,
				ParamType::Uint(256),
			],
			&data,
		)?;
		match (
			tokens[0].clone(),
			tokens[1].clone(),
			tokens[2].clone(),
			tokens[3].clone(),
			tokens[4].clone(),
		) {
			(
                Token::FixedBytes(_signature),
				Token::Uint(chain_id),
				Token::Address(token),
				Token::Address(recipient),
				Token::Uint(amount),
			) => Ok(TokenLockedInfo {
				chain_id,
				token,
				recipient,
				amount,
			}),
			_ => Err(Error::InvalidData),
		}
	}
}
