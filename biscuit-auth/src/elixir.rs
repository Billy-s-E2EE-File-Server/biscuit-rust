use std::{
    collections::{BTreeSet, HashMap},
    iter::FromIterator,
};

use crate::{
    builder::{fact, string, BiscuitBuilder, Fact, Term},
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
fn authorize(biscuit: String, public_key: String, authorizer_code: String) -> bool {
    let public_key = PublicKey::from_bytes_hex(&public_key).unwrap();
    // This does verification for us as well, nice :)
    let biscuit = Biscuit::from(biscuit, public_key).unwrap();
    let mut authorizer = Authorizer::new();
    authorizer.add_code(authorizer_code).unwrap();
    authorizer.add_token(&biscuit).unwrap();
    authorizer.authorize().is_ok()
}

rustler::init!(
    "Elixir.Biscuit",
    [
        new_private_key,
        generate,
        authorize,
        public_key_from_private
    ]
);
