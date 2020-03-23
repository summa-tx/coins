use crate::{
    enc::encoders::{
        NetworkEncoder,
        MainnetEncoder,
        TestnetEncoder,
        SignetEncoder,
    },
};

use std::marker::PhantomData;

// TODO: Add tx types here
pub struct Network<Enc: NetworkEncoder> {
    encoder: PhantomData<Enc>,
}

pub type BitcoinMainnet = Network<MainnetEncoder>;
pub type BitcoinRegtest = Network<TestnetEncoder>;
pub type BitcoinSignet = Network<SignetEncoder>;
