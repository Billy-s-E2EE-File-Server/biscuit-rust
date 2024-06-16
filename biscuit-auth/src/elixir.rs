use std::{collections::BTreeSet, iter::FromIterator, time::Duration};

use chacha20poly1305::{aead::Aead, KeyInit, Nonce, XChaCha20Poly1305};
use rustler::Binary;

use crate::{
    builder::{fact, string, BiscuitBuilder, Fact, Term},
    datalog::RunLimits,
    Authorizer, Biscuit, KeyPair, PrivateKey, PublicKey,
};

#[rustler::nif]
fn new_private_key() -> String {
    let root = KeyPair::new();
    root.private().to_bytes_hex()
}

#[rustler::nif]
fn public_key_from_private(private_key: String) -> String {
    let private_key = PrivateKey::from_bytes_hex(&private_key).unwrap();
    private_key.public().to_bytes_hex()
}

#[rustler::nif]
fn generate(private_key: String, facts: Vec<(String, String, Vec<String>)>) -> String {
    let private_key = PrivateKey::from_bytes_hex(&private_key).unwrap();
    let root = KeyPair::from(&private_key);

    let mut builder = BiscuitBuilder::new();

    facts
        .into_iter()
        .for_each(|(fact_name, fact_type, fact_attributes)| {
            let fact_terms: Vec<Term> = fact_attributes[..]
                .into_iter()
                .map(|attr| string(attr))
                .collect();

            let fact_term: Term = match fact_type.as_str() {
                "string" => fact_terms.first().unwrap().into(),
                "set" => {
                    let fact_terms: BTreeSet<Term> = BTreeSet::from_iter(fact_terms.into_iter());
                    fact_terms.into()
                }
                data_type => todo!("Unknown data type: {data_type}"),
            };

            let fact: Fact = fact(&fact_name, &[fact_term]);
            builder.add_fact(fact).unwrap();
        });

    let biscuit = builder.build(&root).unwrap();
    biscuit.to_base64().unwrap()
}

#[rustler::nif]
fn get_user_id(biscuit: String, public_key: String) -> i64 {
    let public_key = PublicKey::from_bytes_hex(&public_key).unwrap();
    let biscuit = Biscuit::from_base64(biscuit, public_key).unwrap();

    let mut authorizer = Authorizer::new();
    authorizer.add_token(&biscuit).unwrap();
    authorizer
        .add_code(
            r#"
        check if user($user);

        allow if true;
        deny if false;
        "#,
        )
        .unwrap();

    let user_info: Vec<(String,)> = authorizer
        .query_with_limits(
            "data($0) <- user($0)",
            RunLimits {
                max_time: Duration::from_secs(60),
                ..Default::default()
            },
        )
        .unwrap();

    user_info.first().unwrap().0.parse().unwrap()
}

#[rustler::nif]
fn authorize(biscuit: String, public_key: String, authorizer_code: String) -> Result<(), String> {
    let public_key = PublicKey::from_bytes_hex(&public_key).map_err(|e| e.to_string())?;
    let biscuit = Biscuit::from_base64(biscuit, public_key).unwrap();
    let mut authorizer = Authorizer::new();
    authorizer
        .add_code(authorizer_code)
        .map_err(|e| e.to_string())?;
    authorizer.add_token(&biscuit).map_err(|e| e.to_string())?;
    authorizer.authorize().map_err(|e| e.to_string())?;
    Ok(())
}

#[rustler::nif]
fn encrypt(message: Binary, key: Binary, nonce: Binary) -> Result<Vec<u8>, String> {
    let key = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|e| e.to_string())?;

    key.encrypt(nonce.as_slice().into(), message.as_slice())
        .map_err(|e| e.to_string())
}

rustler::init!(
    "Elixir.Biscuit",
    [
        new_private_key,
        generate,
        authorize,
        public_key_from_private,
        get_user_id,
        encrypt,
    ]
);
