use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::{ContractParameters, Error, Outcome, PlayerIndex, TicketedDLC, WinCondition};

use std::borrow::Borrow;

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Outcome::Attestation(i) => write!(f, "att{}", i),
            Outcome::Expiry => write!(f, "exp"),
        }
    }
}

impl std::str::FromStr for Outcome {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "exp" => Ok(Outcome::Expiry),
            s => {
                let index_str = s.strip_prefix("att").ok_or(Error)?;
                let outcome_index = index_str.parse().map_err(|_| Error)?;
                Ok(Outcome::Attestation(outcome_index))
            }
        }
    }
}

impl Serialize for Outcome {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        if ser.is_human_readable() {
            self.to_string().serialize(ser)
        } else {
            match self {
                &Outcome::Attestation(i) => (i as i64).serialize(ser),
                Outcome::Expiry => (-1i64).serialize(ser),
            }
        }
    }
}

impl<'de> Deserialize<'de> for Outcome {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Outcome, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            s.parse().map_err(|_| {
                D::Error::invalid_value(
                    serde::de::Unexpected::Str(&s),
                    &"an attestation or expiry outcome string",
                )
            })
        } else {
            let index = i64::deserialize(deserializer)?;
            if index < 0 {
                Ok(Outcome::Expiry)
            } else {
                Ok(Outcome::Attestation(index as usize))
            }
        }
    }
}

impl std::fmt::Display for WinCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:p{}", self.outcome, self.player_index)
    }
}

impl std::str::FromStr for WinCondition {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (prefix, suffix) = s.split_once(":").ok_or(Error)?;
        let outcome: Outcome = prefix.parse()?;
        let player_index_str = suffix.strip_prefix("p").ok_or(Error)?;
        let player_index = player_index_str.parse().map_err(|_| Error)?;
        Ok(WinCondition {
            outcome,
            player_index,
        })
    }
}

impl Serialize for WinCondition {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        if ser.is_human_readable() {
            self.to_string().serialize(ser)
        } else {
            (self.outcome, self.player_index).serialize(ser)
        }
    }
}

impl<'de> Deserialize<'de> for WinCondition {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<WinCondition, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            s.parse().map_err(|_| {
                D::Error::invalid_value(serde::de::Unexpected::Str(&s), &"a win condition string")
            })
        } else {
            let (outcome, player_index) = <(Outcome, PlayerIndex)>::deserialize(deserializer)?;
            Ok(WinCondition {
                outcome,
                player_index,
            })
        }
    }
}

/// Ticketed DLCs can be perfectly reconstructed from their `ContractParameters`
/// and funding outpoint, so to avoid consuming excess bandwidth, we store only
/// these two fields.
#[derive(Serialize, Deserialize)]
struct CompactTicketedDLC<T: Borrow<ContractParameters>> {
    params: T,
    funding_outpoint: bitcoin::OutPoint,
}

impl Serialize for TicketedDLC {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        (CompactTicketedDLC {
            params: self.params(),
            funding_outpoint: self.funding_outpoint,
        })
        .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for TicketedDLC {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<TicketedDLC, D::Error> {
        let dlc = CompactTicketedDLC::<ContractParameters>::deserialize(deserializer)?;
        TicketedDLC::new(dlc.params, dlc.funding_outpoint).map_err(|err| {
            D::Error::custom(format!(
                "failed to build transactions from deserialized ContractParameters: {}",
                err
            ))
        })
    }
}

pub(crate) mod byte_array {
    use serde::{Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(value: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(value, ser)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let mut bytes = [0u8; 32];
        serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        Ok(bytes)
    }
}

pub(crate) mod vec_of_byte_vecs {
    use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};
    use serdect::slice::HexOrBin;

    pub(crate) fn serialize<S: Serializer>(vecs: &Vec<Vec<u8>>, ser: S) -> Result<S::Ok, S::Error> {
        if !ser.is_human_readable() {
            return vecs.serialize(ser);
        }
        let mut seq = ser.serialize_seq(Some(vecs.len()))?;
        for vec in vecs {
            let slice: &[u8] = vec.as_ref();
            seq.serialize_element(&hex::encode(slice))?;
        }
        seq.end()
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        Ok(
            Vec::<serdect::slice::HexOrBin<false>>::deserialize(deserializer)?
                .into_iter()
                .map(|HexOrBin(vec)| vec)
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventAnnouncement, MarketMaker, PayoutWeights, Player};

    use bitcoin::{Amount, FeeRate};
    use hex::ToHex;
    use std::collections::BTreeMap;

    #[test]
    fn player_serialization() {
        let player = Player {
            pubkey: secp::Scalar::try_from(10).unwrap() * secp::G,
            ticket_hash: [10; 32],
            payout_hash: [20; 32],
        };

        let json_serialized = serde_json::to_string(&player).unwrap();
        assert_eq!(
            &json_serialized,
            "{\"pubkey\":\"03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7\",\
             \"ticket_hash\":\"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a\",\
             \"payout_hash\":\"1414141414141414141414141414141414141414141414141414141414141414\"}",
        );

        let cbor_serialized_hex: String = serde_cbor::to_vec(&player).unwrap().encode_hex();
        assert_eq!(
            &cbor_serialized_hex,
            "a3667075626b657998210318a01843184d189e184718f318c8186218351847187c187b181a18\
             e618ae185d1834184218d4189b1819184318c218b7185218a6188e182a184718e2184718c76b\
             7469636b65745f6861736898200a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a\
             0a0a0a0a0a0a0a6b7061796f75745f6861736898201414141414141414141414141414141414\
             141414141414141414141414141414"
        );
    }

    #[test]
    fn contract_parameters_serialization() {
        let params = ContractParameters {
            market_maker: MarketMaker {
                pubkey: "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7"
                    .parse()
                    .unwrap(),
            },
            players: vec![
                Player {
                    pubkey: secp::Scalar::try_from(10).unwrap() * secp::G,
                    ticket_hash: [10; 32],
                    payout_hash: [20; 32],
                },
                Player {
                    pubkey: secp::Scalar::try_from(11).unwrap() * secp::G,
                    ticket_hash: [30; 32],
                    payout_hash: [40; 32],
                },
            ],
            event: EventAnnouncement {
                oracle_pubkey: "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7"
                    .parse()
                    .unwrap(),
                nonce_point: "0317aec4eea8a2b02c38e6b67c26015d16c82a3a44abc28d1def124c1f79786fc5"
                    .parse()
                    .unwrap(),
                outcome_messages: vec![
                    Vec::from(b"option 1"),
                    Vec::from(b"option 2"),
                    Vec::from(b"option 3"),
                ],
                expiry: Some(u32::MAX),
            },
            outcome_payouts: BTreeMap::from([
                (Outcome::Attestation(0), PayoutWeights::from([(0, 1)])),
                (Outcome::Attestation(1), PayoutWeights::from([(1, 1)])),
                (
                    Outcome::Attestation(2),
                    PayoutWeights::from([(0, 1), (1, 1)]),
                ),
                (Outcome::Expiry, PayoutWeights::from([(0, 1), (1, 1)])),
            ]),
            fee_rate: FeeRate::from_sat_per_vb_unchecked(100),
            funding_value: Amount::from_sat(300_000),
            relative_locktime_block_delta: 25,
        };

        let json_serialized =
            serde_json::to_string_pretty(&params).expect("failed to serialize ContractParameters");

        let json_expected = r#"{
  "market_maker": {
    "pubkey": "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7"
  },
  "players": [
    {
      "pubkey": "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
      "ticket_hash": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
      "payout_hash": "1414141414141414141414141414141414141414141414141414141414141414"
    },
    {
      "pubkey": "03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb",
      "ticket_hash": "1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e",
      "payout_hash": "2828282828282828282828282828282828282828282828282828282828282828"
    }
  ],
  "event": {
    "oracle_pubkey": "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
    "nonce_point": "0317aec4eea8a2b02c38e6b67c26015d16c82a3a44abc28d1def124c1f79786fc5",
    "outcome_messages": [
      "6f7074696f6e2031",
      "6f7074696f6e2032",
      "6f7074696f6e2033"
    ],
    "expiry": 4294967295
  },
  "outcome_payouts": {
    "att0": {
      "0": 1
    },
    "att1": {
      "1": 1
    },
    "att2": {
      "0": 1,
      "1": 1
    },
    "exp": {
      "0": 1,
      "1": 1
    }
  },
  "fee_rate": 25000,
  "funding_value": 300000,
  "relative_locktime_block_delta": 25
}"#;

        assert_eq!(&json_serialized, json_expected);

        let decoded_params: ContractParameters = serde_json::from_str(&json_serialized)
            .expect("failed to deserialize ContractParameters");
        assert_eq!(decoded_params, params);
    }
}
