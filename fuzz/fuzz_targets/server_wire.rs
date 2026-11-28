#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::Serialize;
use serde::de::DeserializeOwned;
use strig_server::wire::{
    AccessRequest, AccessResponse, BatchRequest, BatchResponse, CheckRequest, CheckResponse, ListRequest, ListResponse,
    WhoRequest, WhoResponse,
};

fn read<T: DeserializeOwned + Serialize>(data: &[u8]) {
    if let Ok(value) = serde_json::from_slice::<T>(data) {
        let json = serde_json::to_vec(&value).expect("a wire body serializes");
        serde_json::from_slice::<T>(&json).expect("a serialized wire body must be readable");
    }
}

fuzz_target!(|data: &[u8]| {
    read::<CheckRequest>(data);
    read::<CheckResponse>(data);
    read::<BatchRequest>(data);
    read::<BatchResponse>(data);
    read::<ListRequest>(data);
    read::<ListResponse>(data);
    read::<WhoRequest>(data);
    read::<WhoResponse>(data);
    read::<AccessRequest>(data);
    read::<AccessResponse>(data);
});
