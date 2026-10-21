//! AI-written tests for `Model`. A submodule of `src/model.rs`.

use super::*;

#[test]
fn high_byte_names_the_model() {
    assert_eq!(Model::from_product_id(0x1011), Model::NanoS);
    assert_eq!(Model::from_product_id(0x1015), Model::NanoS);
    assert_eq!(Model::from_product_id(0x4011), Model::NanoX);
    assert_eq!(Model::from_product_id(0x5011), Model::NanoSPlus);
    assert_eq!(Model::from_product_id(0x6011), Model::Stax);
    assert_eq!(Model::from_product_id(0x7011), Model::Flex);
}

#[test]
fn legacy_codes_are_whole_ids() {
    assert_eq!(Model::from_product_id(0x0000), Model::Blue);
    assert_eq!(Model::from_product_id(0x0001), Model::NanoS);
    assert_eq!(Model::from_product_id(0x0004), Model::NanoX);
    assert_eq!(Model::from_product_id(0x0005), Model::NanoSPlus);
    assert_eq!(Model::from_product_id(0x0006), Model::Stax);
    assert_eq!(Model::from_product_id(0x0007), Model::Flex);
}

#[test]
fn unknown_keeps_the_whole_id() {
    assert_eq!(Model::from_product_id(0x8011), Model::Unknown(0x8011));
    assert_eq!(Model::Unknown(0x8011).to_string(), "unknown model 0x8011");
}

#[test]
fn display_matches_the_product_strings() {
    assert_eq!(Model::NanoS.to_string(), "Nano S");
    assert_eq!(Model::NanoSPlus.to_string(), "Nano S Plus");
    assert_eq!(Model::Flex.to_string(), "Flex");
}
