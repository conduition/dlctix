use bitcoin::Amount;
use common::{ClientHello, Intent, ServerHello};
use dlctix::secp::Scalar;
use dlctix::{hashlock, Outcome};

use std::{env, error::Error, net};

fn run_client() -> Result<(), Box<dyn Error>> {
    let market_maker_server_address = env::var("MM_SERVER_ADDRESS")?;

    let mut rng = rand::thread_rng();

    let payout_preimage = hashlock::preimage_random(&mut rng);
    let payout_hash = hashlock::sha256(&payout_preimage);

    let seckey = Scalar::random(&mut rng);
    let pubkey = seckey.base_point_mul();

    println!("secret key: {:x}", seckey);
    println!("  public key: {:x}", pubkey);
    println!("");
    println!("payout preimage: {}", hex::encode(&payout_preimage));
    println!("  payout hash: {}", hex::encode(&payout_hash));
    println!("");

    println!("Connecting to {}...", market_maker_server_address);
    let conn = net::TcpStream::connect(&market_maker_server_address)?;

    println!("Connection established; sending ClientHello...");
    serde_cbor::to_writer(
        &conn,
        &ClientHello {
            player_pubkey: pubkey,
            payout_hash,
        },
    )?;

    let server_hello: ServerHello = serde_cbor::from_reader(&conn)?;
    println!(
        "received ServerHello: {}",
        serde_json::to_string_pretty(&server_hello).unwrap()
    );

    let intent = Intent {
        outcome: Outcome::Attestation(0),
        budget: Amount::from_sat(200_000),
    };
    println!(
        "sending Intent: {}",
        serde_json::to_string_pretty(&intent).unwrap()
    );
    serde_cbor::to_writer(&conn, &intent)?;

    Ok(())
}

fn main() {
    if let Err(e) = run_client() {
        eprintln!("fatal error: {}", e);
        std::process::exit(1);
    }
    println!("exiting OK");
}
