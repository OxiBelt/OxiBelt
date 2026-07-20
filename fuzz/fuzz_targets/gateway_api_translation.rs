#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    oxibelt_gateway_controller::fuzzing::exercise_gateway_api_translation(data);
});
