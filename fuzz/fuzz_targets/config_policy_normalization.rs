#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    oxibelt::fuzzing::exercise_config_policy_normalization(data);
    oxibeltctl::fuzzing::exercise_config_policy_normalization(data);
});
