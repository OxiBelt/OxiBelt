pub(super) fn logical_lines(raw: &str) -> Vec<String> {
  let mut lines = Vec::new();
  let mut current = String::new();
  for line in raw.lines() {
    let trimmed = line.trim_end();
    if let Some(prefix) = trimmed.strip_suffix('\\') {
      current.push_str(prefix);
      current.push(' ');
    } else {
      current.push_str(trimmed);
      lines.push(current.trim().to_string());
      current.clear();
    }
  }
  if !current.trim().is_empty() {
    lines.push(current.trim().to_string());
  }
  lines
}

pub(super) fn strip_comment(line: &str) -> String {
  let mut quoted = false;
  let mut quote = '\0';
  let mut out = String::new();
  for ch in line.chars() {
    if quoted {
      if ch == quote {
        quoted = false;
      }
      out.push(ch);
      continue;
    }
    if matches!(ch, '"' | '\'') {
      quoted = true;
      quote = ch;
      out.push(ch);
      continue;
    }
    if ch == '#' {
      break;
    }
    out.push(ch);
  }
  out
}

pub(super) fn parse_quoted_sections(raw: &str) -> Vec<String> {
  let mut sections = Vec::new();
  let mut chars = raw.trim().chars().peekable();
  while chars.peek().is_some() {
    while matches!(chars.peek(), Some(ch) if ch.is_whitespace()) {
      chars.next();
    }
    let Some(ch) = chars.next() else {
      break;
    };
    if matches!(ch, '"' | '\'') {
      let quote = ch;
      let mut section = String::new();
      for ch in chars.by_ref() {
        if ch == quote {
          break;
        } else {
          section.push(ch);
        }
      }
      sections.push(section);
    } else {
      let mut section = String::new();
      section.push(ch);
      while let Some(ch) = chars.peek().copied() {
        if ch.is_whitespace() {
          break;
        }
        section.push(ch);
        chars.next();
      }
      sections.push(section);
    }
  }
  sections
}

pub(super) fn split_actions(raw: &str) -> Vec<String> {
  let mut tokens = Vec::new();
  let mut current = String::new();
  let mut quoted = false;
  let mut quote = '\0';
  for ch in raw.chars() {
    if quoted {
      if ch == quote {
        quoted = false;
      }
      current.push(ch);
    } else if matches!(ch, '"' | '\'') {
      quoted = true;
      quote = ch;
      current.push(ch);
    } else if ch == ',' {
      tokens.push(current.trim().to_string());
      current.clear();
    } else {
      current.push(ch);
    }
  }
  if !current.trim().is_empty() {
    tokens.push(current.trim().to_string());
  }
  tokens
}

pub(super) fn split_phrases(raw: &str) -> Vec<String> {
  raw
    .split_whitespace()
    .map(unquote)
    .map(ToString::to_string)
    .collect()
}

pub(super) fn unquote(value: &str) -> &str {
  value
    .trim()
    .strip_prefix('\'')
    .and_then(|value| value.strip_suffix('\''))
    .or_else(|| {
      value
        .trim()
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    })
    .unwrap_or_else(|| value.trim())
}

pub(super) fn unquote_selector(value: &str) -> String {
  unquote(value).to_string()
}
