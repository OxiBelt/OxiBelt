//! CRS transform implementations.
//! Transforms operate on derived values and never rewrite upstream-bound metadata.

use std::borrow::Cow;

use anyhow::bail;

use super::super::normalization::{normalize_path, normalize_text};
use super::compatibility::SUPPORTED_TRANSFORMS;

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
    if !SUPPORTED_TRANSFORMS.contains(&raw) {
      bail!("unsupported CRS transform t:{raw}");
    }
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
      _ => bail!("CRS compatibility matrix lists unimplemented transform t:{raw}"),
    }
  }
}

pub(super) fn apply_transforms<'a>(value: &'a str, transforms: &[CrsTransform]) -> Cow<'a, str> {
  if transforms.is_empty() {
    return Cow::Borrowed(value);
  }

  let mut out = Cow::Borrowed(value);
  for transform in transforms {
    let value = out.as_ref();
    out = Cow::Owned(match transform {
      CrsTransform::Lowercase => value.to_ascii_lowercase(),
      CrsTransform::UrlDecode => normalize_text(value),
      CrsTransform::NormalizePath => normalize_path(value),
      CrsTransform::RemoveNulls => value.replace('\0', ""),
      CrsTransform::CompressWhitespace => compress_whitespace(value),
      CrsTransform::RemoveWhitespace => value.chars().filter(|ch| !ch.is_whitespace()).collect(),
      CrsTransform::Trim => value.trim().to_string(),
      CrsTransform::HtmlEntityDecode => decode_html_entities(value),
    });
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
