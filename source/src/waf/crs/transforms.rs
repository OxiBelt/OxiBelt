use anyhow::bail;

use super::super::normalization::{normalize_path, normalize_text};

#[derive(Clone)]
pub(super) enum CrsTransform {
  Lowercase,
  UrlDecode,
  NormalizePath,
  RemoveNulls,
  CompressWhitespace,
  RemoveWhitespace,
  Trim,
  HtmlEntityDecode,
}

impl CrsTransform {
  pub(super) fn parse(raw: &str) -> anyhow::Result<Option<Self>> {
    match raw {
      "none" => Ok(None),
      "lowercase" => Ok(Some(Self::Lowercase)),
      "urlDecode" | "urlDecodeUni" => Ok(Some(Self::UrlDecode)),
      "normalizePath" | "normalizePathWin" => Ok(Some(Self::NormalizePath)),
      "removeNulls" | "replaceNulls" => Ok(Some(Self::RemoveNulls)),
      "compressWhitespace" => Ok(Some(Self::CompressWhitespace)),
      "removeWhitespace" => Ok(Some(Self::RemoveWhitespace)),
      "trim" | "trimLeft" | "trimRight" => Ok(Some(Self::Trim)),
      "htmlEntityDecode" | "jsDecode" | "cssDecode" | "cmdLine" | "utf8toUnicode" => {
        Ok(Some(Self::HtmlEntityDecode))
      }
      _ => bail!("unsupported CRS transform t:{raw}"),
    }
  }
}

pub(super) fn apply_transforms(value: &str, transforms: &[CrsTransform]) -> String {
  let mut out = value.to_string();
  for transform in transforms {
    out = match transform {
      CrsTransform::Lowercase => out.to_ascii_lowercase(),
      CrsTransform::UrlDecode => normalize_text(&out),
      CrsTransform::NormalizePath => normalize_path(&out),
      CrsTransform::RemoveNulls => out.replace('\0', ""),
      CrsTransform::CompressWhitespace => compress_whitespace(&out),
      CrsTransform::RemoveWhitespace => out.chars().filter(|ch| !ch.is_whitespace()).collect(),
      CrsTransform::Trim => out.trim().to_string(),
      CrsTransform::HtmlEntityDecode => decode_html_entities(&out),
    };
  }
  out
}

fn compress_whitespace(value: &str) -> String {
  let mut out = String::new();
  let mut space = false;
  for ch in value.chars() {
    if ch.is_whitespace() {
      if !space {
        out.push(' ');
        space = true;
      }
    } else {
      out.push(ch);
      space = false;
    }
  }
  out
}

fn decode_html_entities(value: &str) -> String {
  value
    .replace("&lt;", "<")
    .replace("&gt;", ">")
    .replace("&amp;", "&")
    .replace("&quot;", "\"")
    .replace("&#x27;", "'")
    .replace("&#39;", "'")
}
