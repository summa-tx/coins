use std::{
    collections::{
        BTreeMap,
        btree_map::{Iter, IterMut},
    },
    io::{Read, Write},
};

use riemann_core::{
    primitives::{PrefixVec},
    ser::{Ser},
};

use crate::
{
    psbt::common::{PSBTError, PSBTKey, PSBTValue},
};

psbt_map!(PSBTInput);
