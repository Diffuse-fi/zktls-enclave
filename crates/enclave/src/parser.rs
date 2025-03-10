use automata_sgx_sdk::types::SgxStatus;
use serde_json::Value;

use crate::{error::SgxResult, HARDCODED_DECIMALS};

pub(crate) fn get_filtered_items<S: AsRef<str>, T: AsRef<str>>(
    server_response: S,
    currency_pairs: &[T],
) -> SgxResult<Vec<(String, u64, u64)>> {
    let parts: Vec<&str> = server_response.as_ref().split("\r\n\r\n").collect();
    if parts.len() < 2 {
        tracing::error!("Unexpected response format");
        return Err(SgxStatus::Unexpected.into());
    }
    let json_body = parts[1].trim();

    let json_from_server: Value = serde_json::from_str(json_body)?;

    let filtered_items: Vec<(String, u64, u64)> = json_from_server
        .as_array()
        .ok_or(SgxStatus::Unexpected)?
        .iter()
        .filter_map(|item| {
            let pair = item["symbol"].as_str()?;

            tracing::debug!("let pair: {}", pair);

            let is_contains = currency_pairs.iter().any(|x| x.as_ref() == pair);

            tracing::debug!("currency_pairs.contains(&pair): {}", is_contains);

            if !is_contains {
                tracing::debug!("!currency_pairs.contains(&pair.to_string())");
                return None;
            }

            let price_str = item["lastPrice"].as_str()?;
            let integer_and_fractional: Vec<&str> = price_str.split('.').collect();

            if integer_and_fractional.len() != 2 {
                panic!("price is not float number!");
            }

            let integer: u64 = integer_and_fractional[0].parse().ok()?;
            let fractional: u64 = integer_and_fractional[1].parse().ok()?;

            let mut price: u64 = integer * 100000000;
            let decimal_points = integer_and_fractional[1].chars().count() as u32;

            assert!(
                decimal_points <= HARDCODED_DECIMALS,
                "price decimal points <= 8 are hardcoded"
            ); // TODO 8 hardcoded

            price += fractional * 10u64.pow(HARDCODED_DECIMALS - decimal_points);

            let timestamp = item["closeTime"].as_u64()?;

            tracing::debug!("pair: {}", pair);
            tracing::debug!("price: {}", price);
            tracing::debug!("timestamp: {}", timestamp);

            Some((pair.to_string(), price, timestamp))
        })
        .collect();

    Ok(filtered_items)
}
