use super::*;
use http::header::HeaderName;

fn headers(values: &[(&str, &str)]) -> HeaderMap {
  let mut headers = HeaderMap::new();
  for (name, value) in values {
    headers.append(
      HeaderName::from_bytes(name.as_bytes()).unwrap(),
      HeaderValue::from_str(value).unwrap(),
    );
  }
  headers
}

fn hash(byte: u8) -> DictionaryHash {
  DictionaryHash::from_slice(&[byte; SHA256_DIGEST_BYTES]).unwrap()
}

fn directive(value: &str, url: &Url) -> UseAsDictionary {
  parse_use_as_dictionary(value.as_bytes(), url).unwrap()
}

fn stored(byte: u8, directive: UseAsDictionary, fetched_at: u64) -> StoredDictionary {
  StoredDictionary {
    hash: hash(byte),
    dictionary_url: Url::parse("https://example.test/dictionary").unwrap(),
    use_as_dictionary: directive,
    fresh_or_stale_allowed: true,
    fetched_at,
  }
}

#[test]
fn available_dictionary_requires_one_sha256_byte_sequence_and_one_id() {
  let encoded = hash(7).to_header_value();
  let parsed = parse_available_dictionary(&headers(&[
    ("available-dictionary", &encoded),
    ("dictionary-id", r#""a\"quoted\\id""#),
  ]))
  .unwrap()
  .unwrap();
  assert_eq!(parsed.hash, hash(7));
  assert_eq!(parsed.id.as_deref(), Some("a\"quoted\\id"));
  assert_eq!(
    parsed
      .canonical_headers(&[DictionaryEncoding::Dcz, DictionaryEncoding::Dcb])
      .unwrap(),
    DictionaryRequestHeaders {
      available_dictionary: encoded,
      dictionary_id: Some(r#""a\"quoted\\id""#.to_owned()),
      accept_encoding: Some("dcz, dcb".to_owned()),
    }
  );

  for invalid in [":AQ==:", "?1", ":AAAA:"] {
    assert!(parse_available_dictionary(&headers(&[("available-dictionary", invalid)])).is_err());
  }
  assert!(
    parse_available_dictionary(&headers(&[
      ("available-dictionary", &hash(1).to_header_value()),
      ("available-dictionary", &hash(2).to_header_value()),
    ]))
    .is_err()
  );
  assert!(parse_available_dictionary(&headers(&[("dictionary-id", r#""orphan""#)])).is_err());
}

#[test]
fn dictionary_id_and_input_limits_are_enforced() {
  let id = "x".repeat(MAX_DICTIONARY_ID_CHARS + 1);
  let encoded = hash(1).to_header_value();
  assert_eq!(
    parse_available_dictionary(&headers(&[
      ("available-dictionary", &encoded),
      ("dictionary-id", &format!("\"{id}\"")),
    ])),
    Err(FieldError::DictionaryIdTooLong)
  );
  let oversized = "x".repeat(MAX_DICTIONARY_FIELD_BYTES + 1);
  assert_eq!(
    parse_use_as_dictionary(
      oversized.as_bytes(),
      &Url::parse("https://example.test/d").unwrap()
    ),
    Err(FieldError::InputTooLong)
  );
}

#[test]
fn use_as_dictionary_requires_match_and_rejects_groups_and_ambiguity() {
  let url = Url::parse("https://example.test/dictionary").unwrap();
  let parsed = directive(
    r#"match="/assets/%C3%A9/*";ignored=1, match-dest=("script" "style"), id="server-1", type=raw, extension=(?1)"#,
    &url,
  );
  assert_eq!(parsed.match_pattern, "/assets/%C3%A9/*");
  assert_eq!(parsed.match_destinations, ["script", "style"]);
  assert_eq!(parsed.id, "server-1");
  assert!(parsed.is_supported());
  assert!(matches!(
    directive(r#"match="/a/*", type=future"#, &url).dictionary_type,
    DictionaryType::Unknown(ref value) if value == "future"
  ));
  for invalid in [
    r#"id="missing""#,
    r#"match=("/a")"#,
    r#"match="/a", match="/b""#,
    r#"match="/users/(.*)""#,
    r#"match="/a", match-dest="script""#,
  ] {
    assert!(
      parse_use_as_dictionary(invalid.as_bytes(), &url).is_err(),
      "{invalid}"
    );
  }
  assert_eq!(
    parse_use_as_dictionary(
      r#"match="/a""#.as_bytes(),
      &Url::parse("http://example.test/d").unwrap()
    ),
    Err(FieldError::InsecureUrl)
  );
}

#[test]
fn use_as_dictionary_serializes_canonically_and_reparses() {
  let url = Url::parse("https://example.test/dictionary").unwrap();
  let declaration = directive(
    r#"type=raw, id="server-\\\"one", match-dest=("script" "style"), match="/assets/*""#,
    &url,
  );
  assert_eq!(
    declaration.to_header_value().unwrap(),
    r#"match="/assets/*", match-dest=("script" "style"), id="server-\\\"one", type=raw"#
  );
  assert_eq!(
    parse_use_as_dictionary(declaration.to_header_value().unwrap().as_bytes(), &url).unwrap(),
    declaration
  );
  assert_eq!(
    UseAsDictionary {
      match_pattern: "/".to_owned(),
      match_destinations: Vec::new(),
      id: String::new(),
      dictionary_type: DictionaryType::Unknown("future".to_owned()),
    }
    .to_header_value(),
    Err(FieldError::InvalidMember)
  );
}

#[test]
fn dictionary_selection_is_same_origin_percent_encoded_and_rfc_ordered() {
  let url = Url::parse("https://example.test/dictionary").unwrap();
  let dictionaries = [
    stored(1, directive(r#"match="/assets/*""#, &url), 99),
    stored(
      2,
      directive(r#"match="/assets/*", match-dest=("script")"#, &url),
      1,
    ),
    stored(
      3,
      directive(r#"match="/assets/%C3%A9/*", match-dest=("script")"#, &url),
      2,
    ),
    stored(
      4,
      directive(r#"match="/assets/%C3%A9/*", match-dest=("script")"#, &url),
      3,
    ),
  ];
  let request = Url::parse("https://example.test/assets/%C3%A9/app.js").unwrap();
  assert_eq!(
    select_dictionary(&dictionaries, &request, Some("script")).map(|dictionary| dictionary.hash),
    Some(hash(4))
  );
  assert_eq!(
    select_dictionary(&dictionaries, &request, Some("style")).map(|dictionary| dictionary.hash),
    Some(hash(1))
  );
  assert_eq!(
    select_dictionary(&dictionaries, &request, None).map(|dictionary| dictionary.hash),
    Some(hash(4))
  );
  assert!(
    select_dictionary(
      &dictionaries,
      &Url::parse("https://other.test/assets/%C3%A9/app.js").unwrap(),
      Some("script"),
    )
    .is_none()
  );
  assert!(
    select_dictionary(
      &dictionaries,
      &Url::parse("http://example.test/assets/%C3%A9/app.js").unwrap(),
      Some("script"),
    )
    .is_none()
  );
}

#[test]
fn encoding_negotiation_requires_hash_and_respects_explicit_zero_and_wildcards() {
  assert_eq!(
    dictionary_accept_encoding(None, &[DictionaryEncoding::Dcb]),
    None
  );
  assert_eq!(
    dictionary_accept_encoding(
      Some(hash(1)),
      &[
        DictionaryEncoding::Dcb,
        DictionaryEncoding::Dcb,
        DictionaryEncoding::Dcz
      ]
    ),
    Some("dcb, dcz".to_owned())
  );
  assert_eq!(
    negotiate_dictionary_encoding(
      Some("dcb;q=0, *;q=1"),
      Some(&hash(1)),
      &[DictionaryEncoding::Dcb, DictionaryEncoding::Dcz]
    ),
    Some(DictionaryEncoding::Dcz)
  );
  assert_eq!(
    negotiate_dictionary_encoding(Some("*;q=1"), None, &[DictionaryEncoding::Dcb]),
    None
  );
  assert_eq!(
    negotiate_dictionary_encoding(Some("dcz;q=0"), Some(&hash(1)), &[DictionaryEncoding::Dcz]),
    None
  );
}

#[test]
fn server_fetch_and_cors_gate_fails_closed_for_ambiguous_or_cross_origin_contexts() {
  let response = headers(&[("access-control-allow-origin", "https://app.example")]);
  let cors = headers(&[
    ("sec-fetch-site", "cross-site"),
    ("sec-fetch-mode", "cors"),
    ("origin", "https://app.example"),
  ]);
  assert!(server_dictionary_compression_eligible(
    &cors,
    &response,
    Some(&hash(1))
  ));
  assert!(!server_dictionary_compression_eligible(
    &cors, &response, None
  ));
  assert!(!server_dictionary_compression_eligible(
    &headers(&[("sec-fetch-site", "cross-site"), ("sec-fetch-mode", "cors")]),
    &response,
    Some(&hash(1)),
  ));
  assert!(!server_dictionary_compression_eligible(
    &headers(&[
      ("sec-fetch-site", "same-origin"),
      ("sec-fetch-site", "cross-site"),
    ]),
    &HeaderMap::new(),
    Some(&hash(1)),
  ));
  assert!(server_dictionary_compression_eligible(
    &headers(&[("sec-fetch-site", "same-origin")]),
    &HeaderMap::new(),
    Some(&hash(1)),
  ));
}
