//! Bounded binary-format probes for WAF body classification.

pub(super) fn bytes_match_format(bytes: &[u8], format: &str) -> bool {
  match normalize_binary_format(format).as_str() {
    "7z" | "7zip" | "application/x-7z-compressed" => bytes.starts_with(b"\x37\x7a\xbc\xaf\x27\x1c"),
    "alac" | "audio/alac" => is_alac(bytes),
    "apng" | "image/apng" => is_apng(bytes),
    "av1" | "video/av1" => is_av1(bytes),
    "avif" | "image/avif" => is_isobmff_with_brand(bytes, &[b"avif", b"avis"]),
    "bzip2" | "bz2" | "application/x-bzip2" => bytes.starts_with(b"BZh"),
    "dirac" | "video/dirac" => bytes.starts_with(b"BBCD"),
    "djvu" | "djv" | "image/vnd.djvu" => bytes.starts_with(b"AT&TFORM"),
    "dvi" | "application/x-dvi" => bytes.starts_with(b"\xf7\x02"),
    "elf" | "linux-exe" | "linux-executable" | "application/x-elf" => bytes.starts_with(b"\x7fELF"),
    "epub" | "application/epub+zip" => is_zip_with(bytes, b"application/epub+zip"),
    "exe"
    | "pe"
    | "pe32"
    | "portable-executable"
    | "windows-exe"
    | "windows-executable"
    | "application/x-msdownload"
    | "application/vnd.microsoft.portable-executable" => is_pe_executable(bytes),
    "exr" | "openexr" | "image/x-exr" => bytes.starts_with(b"\x76\x2f\x31\x01"),
    "flac" | "audio/flac" => bytes.starts_with(b"fLaC"),
    "flif" | "image/flif" => bytes.starts_with(b"FLIF"),
    "gbr" | "gimp-brush" | "image/x-gimp-gbr" => is_gbr(bytes),
    "gif" | "image/gif" => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
    "glb" | "gltf-binary" | "model/gltf-binary" => bytes.starts_with(b"glTF"),
    "gzip" | "gz" | "application/gzip" | "application/x-gzip" => bytes.starts_with(b"\x1f\x8b\x08"),
    "hdf" | "hdf4" | "application/x-hdf" => {
      bytes.starts_with(b"\x0e\x03\x13\x01") || is_hdf5(bytes)
    }
    "hdf5" | "h5" | "application/x-hdf5" => is_hdf5(bytes),
    "jpeg" | "jpg" | "image/jpeg" => bytes.starts_with(b"\xff\xd8\xff"),
    "jpeg-2000" | "jpeg2000" | "jp2" | "j2k" | "image/jp2" => is_jpeg_2000(bytes),
    "jpeg-xl" | "jpegxl" | "jxl" | "image/jxl" => is_jpeg_xl(bytes),
    "lzip" | "application/x-lzip" => bytes.starts_with(b"LZIP"),
    "maff" | "application/x-maff" => is_zip_with(bytes, b"index.rdf"),
    "matroska" | "mkv" | "video/x-matroska" => is_ebml_doctype(bytes, b"matroska"),
    "mng" | "video/x-mng" => bytes.starts_with(b"\x8aMNG\r\n\x1a\n"),
    "mp3" | "audio/mpeg" => is_mp3(bytes),
    "musepack" | "mpc" | "audio/x-musepack" => {
      bytes.starts_with(b"MPCK") || bytes.starts_with(b"MP+")
    }
    "netcdf" | "nc" | "application/x-netcdf" => is_netcdf(bytes),
    "odf" | "odt" | "ods" | "odp" | "odg" | "opendocument" => {
      is_zip_with(bytes, b"application/vnd.oasis.opendocument")
    }
    "ogg" | "application/ogg" | "audio/ogg" | "video/ogg" => is_ogg(bytes),
    "ooxml" | "office-open-xml" | "docx" | "xlsx" | "pptx" => is_ooxml(bytes),
    "openraster" | "ora" | "image/openraster" => is_zip_with(bytes, b"application/x-openraster"),
    "openxps" | "oxps" | "xps" | "application/oxps" | "application/vnd.ms-xpsdocument" => {
      is_openxps(bytes)
    }
    "opus" | "audio/opus" => is_ogg_with(bytes, b"OpusHead"),
    "pdf" | "pdf-a" | "pdf-e" | "pdf-raster" | "pdf-ua" | "pdf-x" | "application/pdf" => {
      bytes.starts_with(b"%PDF-")
    }
    "png" | "image/png" => is_png(bytes),
    "qoi" | "image/qoi" => bytes.starts_with(b"qoif"),
    "speex" | "audio/speex" => is_ogg_with(bytes, b"Speex   "),
    "tar" | "application/x-tar" => is_tar(bytes),
    "theora" | "video/theora" => is_ogg_with(bytes, b"\x80theora"),
    "vorbis" | "audio/vorbis" => is_ogg_with(bytes, b"\x01vorbis"),
    "wavpack" | "wv" | "audio/wavpack" => bytes.starts_with(b"wvpk"),
    "webp" | "image/webp" => is_webp(bytes),
    "zip" | "application/zip" | "application/x-zip-compressed" => is_zip(bytes),
    "webm" | "video/webm" | "audio/webm" => is_ebml_doctype(bytes, b"webm"),
    "woff" | "font/woff" => bytes.starts_with(b"wOFF"),
    "woff2" | "font/woff2" => bytes.starts_with(b"wOF2"),
    "xcf" | "image/x-xcf" => bytes.starts_with(b"gimp xcf "),
    "xz" | "application/x-xz" => bytes.starts_with(b"\xfd7zXZ\x00"),
    "zim" | "application/x-zim" => bytes.starts_with(b"ZIM\x04"),
    _ => false,
  }
}

fn normalize_binary_format(format: &str) -> String {
  format.trim().to_ascii_lowercase().replace(['_', ' '], "-")
}

fn is_zip(bytes: &[u8]) -> bool {
  bytes.starts_with(b"PK\x03\x04")
    || bytes.starts_with(b"PK\x05\x06")
    || bytes.starts_with(b"PK\x07\x08")
}

fn is_png(bytes: &[u8]) -> bool {
  bytes.starts_with(b"\x89PNG\r\n\x1a\n")
}

fn is_apng(bytes: &[u8]) -> bool {
  is_png(bytes) && png_contains_chunk(bytes, b"acTL")
}

fn png_contains_chunk(bytes: &[u8], chunk_type: &[u8; 4]) -> bool {
  let mut offset = 8usize;
  while offset + 8 <= bytes.len() {
    let length = u32::from_be_bytes([
      bytes[offset],
      bytes[offset + 1],
      bytes[offset + 2],
      bytes[offset + 3],
    ]) as usize;
    if &bytes[offset + 4..offset + 8] == chunk_type {
      return true;
    }
    let Some(next) = offset
      .checked_add(8)
      .and_then(|offset| offset.checked_add(length))
      .and_then(|offset| offset.checked_add(4))
    else {
      return false;
    };
    if next <= offset {
      return false;
    }
    offset = next;
  }
  false
}

fn is_webp(bytes: &[u8]) -> bool {
  bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP"
}

fn is_gbr(bytes: &[u8]) -> bool {
  bytes.len() >= 24 && &bytes[20..24] == b"GIMP"
}

fn is_jpeg_2000(bytes: &[u8]) -> bool {
  bytes.starts_with(b"\x00\x00\x00\x0cjP  \r\n\x87\n") || bytes.starts_with(b"\xff\x4f\xff\x51")
}

fn is_jpeg_xl(bytes: &[u8]) -> bool {
  bytes.starts_with(b"\xff\x0a") || is_isobmff_with_brand(bytes, &[b"jxl "])
}

fn is_isobmff_with_brand(bytes: &[u8], brands: &[&[u8; 4]]) -> bool {
  if bytes.len() < 12 || &bytes[4..8] != b"ftyp" {
    return false;
  }
  if brands.iter().any(|brand| &bytes[8..12] == brand.as_slice()) {
    return true;
  }

  let box_size = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
  let limit = if box_size >= 16 && box_size <= bytes.len() {
    box_size
  } else {
    bytes.len().min(256)
  };
  if limit <= 16 {
    return false;
  }
  bytes[16..limit]
    .chunks_exact(4)
    .any(|brand| brands.iter().any(|expected| brand == expected.as_slice()))
}

fn is_alac(bytes: &[u8]) -> bool {
  bytes.len() >= 12 && &bytes[4..8] == b"ftyp" && byte_contains(bytes, b"alac")
}

fn is_av1(bytes: &[u8]) -> bool {
  (bytes.len() >= 12 && bytes.starts_with(b"DKIF") && &bytes[8..12] == b"AV01")
    || is_isobmff_with_brand(bytes, &[b"av01"])
}

fn is_ogg(bytes: &[u8]) -> bool {
  bytes.starts_with(b"OggS")
}

fn is_ogg_with(bytes: &[u8], marker: &[u8]) -> bool {
  is_ogg(bytes) && byte_contains(bytes, marker)
}

fn is_mp3(bytes: &[u8]) -> bool {
  bytes.starts_with(b"ID3") || (bytes.len() >= 2 && bytes[0] == 0xff && (bytes[1] & 0xe0) == 0xe0)
}

fn is_tar(bytes: &[u8]) -> bool {
  bytes.len() >= 263 && (&bytes[257..263] == b"ustar\0" || &bytes[257..263] == b"ustar ")
}

fn is_ooxml(bytes: &[u8]) -> bool {
  is_zip(bytes)
    && byte_contains(bytes, b"[Content_Types].xml")
    && (byte_contains(bytes, b"word/")
      || byte_contains(bytes, b"xl/")
      || byte_contains(bytes, b"ppt/"))
}

fn is_openxps(bytes: &[u8]) -> bool {
  is_zip(bytes)
    && (byte_contains(bytes, b"FixedDocumentSequence.fdseq")
      || byte_contains(bytes, b"application/vnd.ms-package.xps")
      || byte_contains(bytes, b"schemas.microsoft.com/xps/"))
}

fn is_zip_with(bytes: &[u8], marker: &[u8]) -> bool {
  is_zip(bytes) && byte_contains(bytes, marker)
}

fn is_hdf5(bytes: &[u8]) -> bool {
  bytes.starts_with(b"\x89HDF\r\n\x1a\n")
}

fn is_netcdf(bytes: &[u8]) -> bool {
  bytes.starts_with(b"CDF\x01") || bytes.starts_with(b"CDF\x02") || bytes.starts_with(b"CDF\x05")
}

fn is_pe_executable(bytes: &[u8]) -> bool {
  if bytes.len() < 0x40 || !bytes.starts_with(b"MZ") {
    return false;
  }
  let pe_offset = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
  pe_offset + 4 <= bytes.len() && &bytes[pe_offset..pe_offset + 4] == b"PE\0\0"
}

fn is_ebml_doctype(bytes: &[u8], expected_doctype: &[u8]) -> bool {
  if !bytes.starts_with(b"\x1a\x45\xdf\xa3") {
    return false;
  }

  let limit = bytes.len().min(4096);
  let header = &bytes[..limit];
  let Some(position) = memchr::memmem::find(header, b"\x42\x82") else {
    return false;
  };
  let Some((size_len, doc_type_len)) = parse_ebml_vint(&header[position + 2..]) else {
    return false;
  };
  let start = position + 2 + size_len;
  let Some(end) = start.checked_add(doc_type_len) else {
    return false;
  };
  end <= header.len() && &header[start..end] == expected_doctype
}

fn byte_contains(bytes: &[u8], needle: &[u8]) -> bool {
  !needle.is_empty() && memchr::memmem::find(bytes, needle).is_some()
}

fn parse_ebml_vint(bytes: &[u8]) -> Option<(usize, usize)> {
  let first = *bytes.first()?;
  for width in 1..=8 {
    let marker = 1u8 << (8 - width);
    if first & marker == 0 {
      continue;
    }
    if bytes.len() < width {
      return None;
    }
    let mut value = u64::from(first & !marker);
    for byte in &bytes[1..width] {
      value = (value << 8) | u64::from(*byte);
    }
    return usize::try_from(value).ok().map(|value| (width, value));
  }
  None
}

#[cfg(test)]
mod tests {
  use super::{byte_contains, is_ebml_doctype};

  #[test]
  fn byte_contains_preserves_empty_needle_behavior_and_finds_unaligned_matches() {
    assert!(!byte_contains(b"payload", b""));
    assert!(byte_contains(b"xunaligned marker", b"marker"));
    assert!(!byte_contains(b"short", b"longer needle"));
  }

  #[test]
  fn ebml_doctype_scan_stays_within_the_first_four_kibibytes() {
    let mut bytes = b"\x1a\x45\xdf\xa3".to_vec();
    bytes.resize(4096, 0);
    bytes.extend_from_slice(b"\x42\x82\x84webm");

    assert!(!is_ebml_doctype(&bytes, b"webm"));
  }
}
