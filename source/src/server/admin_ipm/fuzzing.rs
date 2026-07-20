use super::{
  IpmBindingCreate, IpmCredentialCreate, IpmCredentialPatch, IpmCredentialRevoke,
  IpmCredentialRotate, IpmPolicyCreate, IpmPolicyPatch, IpmPrincipalCreate, IpmPrincipalPatch,
};

pub(crate) fn fuzz_decode_mutation_body(selector: u8, data: &[u8]) {
  match selector % 9 {
    0 => drop(serde_json::from_slice::<IpmPrincipalCreate>(data)),
    1 => drop(serde_json::from_slice::<IpmPrincipalPatch>(data)),
    2 => drop(serde_json::from_slice::<IpmCredentialCreate>(data)),
    3 => drop(serde_json::from_slice::<IpmCredentialPatch>(data)),
    4 => drop(serde_json::from_slice::<IpmCredentialRotate>(data)),
    5 => drop(serde_json::from_slice::<IpmCredentialRevoke>(data)),
    6 => drop(serde_json::from_slice::<IpmPolicyCreate>(data)),
    7 => drop(serde_json::from_slice::<IpmPolicyPatch>(data)),
    _ => drop(serde_json::from_slice::<IpmBindingCreate>(data)),
  }
}
