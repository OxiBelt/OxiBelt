use super::{select_admin_certificate_by_names, sni_matches};

#[test]
fn sni_matches_without_lowercase_allocation() {
  assert!(sni_matches("admin.example.test", "Admin.Example.Test"));
  assert!(sni_matches("*.example.test", "Admin.Example.Test"));
  assert!(!sni_matches("*.example.test", "deep.admin.example.test"));
  assert!(!sni_matches("*.example.test", "example.test"));
}

#[test]
fn admin_certificate_selection_prefers_exact_name_before_wildcard() {
  let certificates = vec![
    vec!["*.example.test".to_string()],
    vec!["admin.example.test".to_string()],
  ];

  let selected =
    select_admin_certificate_by_names(&certificates, "Admin.Example.Test", Vec::as_slice)
      .expect("admin certificate should match");

  assert_eq!(selected, &certificates[1]);
}
