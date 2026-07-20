#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    oxibelt::fuzzing::exercise_admin_json_mutations(data);
});
