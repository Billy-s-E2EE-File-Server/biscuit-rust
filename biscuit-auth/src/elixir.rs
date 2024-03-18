use crate::{
    builder::{fact, string, BiscuitBuilder, Fact, Term},
    Authorizer, Biscuit, KeyPair, PrivateKey, PublicKey,
};

#[rustler::nif]
fn new_private_key() -> Vec<u8> {
    let root = KeyPair::new();
    root.private().to_bytes().to_vec()
}

#[rustler::nif]
fn public_key_from_private(private_key: Vec<u8>) -> Vec<u8> {
    let private_key = PrivateKey::from_bytes(&private_key).unwrap();
    private_key.public().to_bytes().to_vec()
}

#[rustler::nif]
fn generate(private_key: Vec<u8>, facts: Vec<Vec<String>>) -> Vec<u8> {
    let private_key = PrivateKey::from_bytes(&private_key).unwrap();
    let root = KeyPair::from(&private_key);

    let mut builder = BiscuitBuilder::new();
    facts.into_iter().for_each(|fact_attributes| {
        let fact_name = &fact_attributes[0];
        let fact_terms: Vec<Term> = fact_attributes[1..]
            .into_iter()
            .map(|attr| string(attr))
            .collect();

        let fact: Fact = fact(&fact_name, &fact_terms);
        builder.add_fact(fact).unwrap();
    });

    let biscuit = builder.build(&root).unwrap();
    biscuit.to_vec().unwrap()
}

#[rustler::nif]
fn authorize(biscuit: Vec<u8>, public_key: Vec<u8>, authorizer_code: String) -> bool {
    let public_key = PublicKey::from_bytes(&public_key).unwrap();
    // This does verification for us as well, nice :)
    let biscuit = Biscuit::from(biscuit, public_key).unwrap();
    let mut authorizer = Authorizer::new();
    authorizer.add_code(authorizer_code).unwrap();
    authorizer.add_token(&biscuit).unwrap();
    authorizer.authorize().is_ok()
}

rustler::init!("Elixir.Biscuit", [new_private_key, generate, authorize]);
