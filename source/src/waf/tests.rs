use super::bytes_match_format;

#[test]
fn binary_format_helper_matches_attachment_formats_with_stable_signatures() {
  let pe = {
    let mut bytes = vec![0u8; 0x84];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes
  };
  let tar = {
    let mut bytes = vec![0u8; 512];
    bytes[257..263].copy_from_slice(b"ustar\0");
    bytes
  };

  let cases: &[(&str, &[u8])] = &[
    ("7z", b"\x37\x7a\xbc\xaf\x27\x1c\x00\x04"),
    ("alac", b"\x00\x00\x00\x18ftypM4A \x00\x00\x00\x00alac"),
    (
      "apng",
      b"\x89PNG\r\n\x1a\n\x00\x00\x00\x00acTL\x00\x00\x00\x00",
    ),
    ("av1", b"DKIF\x00\x00\x00\x00AV01"),
    ("avif", b"\x00\x00\x00\x18ftypavif\x00\x00\x00\x00mif1"),
    ("bzip2", b"BZh9"),
    ("dirac", b"BBCD"),
    ("djvu", b"AT&TFORM"),
    ("dvi", b"\xf7\x02"),
    ("elf", b"\x7fELF\x02\x01\x01"),
    ("epub", b"PK\x03\x04mimetypeapplication/epub+zip"),
    ("exr", b"\x76\x2f\x31\x01"),
    ("flac", b"fLaC"),
    ("flif", b"FLIF"),
    (
      "gbr",
      b"\x00\x00\x00\x1c\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x04GIMP",
    ),
    ("gif", b"GIF89a"),
    ("glb", b"glTF\x02\x00\x00\x00"),
    ("gzip", b"\x1f\x8b\x08"),
    ("hdf4", b"\x0e\x03\x13\x01"),
    ("hdf5", b"\x89HDF\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff\xe0"),
    ("jpeg-2000", b"\x00\x00\x00\x0cjP  \r\n\x87\n"),
    ("jpeg-xl", b"\xff\x0a"),
    ("lzip", b"LZIP"),
    ("maff", b"PK\x03\x04index.rdf"),
    ("mkv", b"\x1a\x45\xdf\xa3\x9f\x42\x82\x88matroska"),
    ("mng", b"\x8aMNG\r\n\x1a\n"),
    ("mp3", b"ID3\x04\x00"),
    ("musepack", b"MPCK"),
    ("netcdf", b"CDF\x01"),
    (
      "odf",
      b"PK\x03\x04mimetypeapplication/vnd.oasis.opendocument.text",
    ),
    ("ogg", b"OggS"),
    ("ooxml", b"PK\x03\x04[Content_Types].xmlword/document.xml"),
    ("openraster", b"PK\x03\x04mimetypeapplication/x-openraster"),
    ("openxps", b"PK\x03\x04FixedDocumentSequence.fdseq"),
    ("opus", b"OggS\x00OpusHead"),
    ("pdf", b"%PDF-1.7"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("qoi", b"qoif"),
    ("speex", b"OggS\x00Speex   "),
    ("theora", b"OggS\x00\x80theora"),
    ("vorbis", b"OggS\x00\x01vorbis"),
    ("wavpack", b"wvpk"),
    ("webm", b"\x1a\x45\xdf\xa3\x9f\x42\x82\x84webm"),
    ("webp", b"RIFF\x00\x00\x00\x00WEBP"),
    ("woff", b"wOFF"),
    ("woff2", b"wOF2"),
    ("xcf", b"gimp xcf "),
    ("xz", b"\xfd7zXZ\x00"),
    ("zim", b"ZIM\x04"),
    ("zip", b"PK\x03\x04"),
  ];

  for (format, bytes) in cases {
    assert!(
      bytes_match_format(bytes, format),
      "expected {format} to match"
    );
  }
  assert!(bytes_match_format(&pe, "windows-exe"));
  assert!(bytes_match_format(&tar, "tar"));
}

#[test]
fn binary_format_helper_leaves_text_and_filesystem_like_formats_unmatched() {
  assert!(!bytes_match_format(b"<svg></svg>", "svg"));
  assert!(!bytes_match_format(b"key: value\n", "yaml"));
  assert!(!bytes_match_format(b"LUKS\xba\xbe", "luks"));
  assert!(!bytes_match_format(b"OBJ text", "obj"));
}

#[test]
fn binary_format_helper_rejects_short_isobmff_without_panicking() {
  for len in 12..=15 {
    let mut bytes = vec![0u8; len];
    bytes[4..8].copy_from_slice(b"ftyp");
    bytes[8..12].copy_from_slice(b"nope");

    assert!(!bytes_match_format(&bytes, "avif"));
    assert!(!bytes_match_format(&bytes, "jpeg-xl"));
    assert!(!bytes_match_format(&bytes, "av1"));
  }
}
