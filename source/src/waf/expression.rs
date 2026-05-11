use anyhow::bail;

use super::{BinaryOp, Expr};

#[derive(Debug, Clone, PartialEq)]
enum Token {
  Ident(String),
  String(String),
  Int(i64),
  True,
  False,
  Null,
  Dot,
  Comma,
  LParen,
  RParen,
  Bang,
  EqEq,
  Ne,
  Lt,
  Le,
  Gt,
  Ge,
  AndAnd,
  OrOr,
  Plus,
  Invalid(char),
  Eof,
}

pub(super) struct Parser {
  tokens: Vec<Token>,
  position: usize,
}

impl Parser {
  pub(super) fn new(input: &str) -> Self {
    Self {
      tokens: tokenize(input),
      position: 0,
    }
  }

  pub(super) fn parse(mut self) -> anyhow::Result<Expr> {
    let expr = self.parse_or()?;
    if !matches!(self.peek(), Token::Eof) {
      bail!("unexpected token {:?}", self.peek());
    }
    Ok(expr)
  }

  fn parse_or(&mut self) -> anyhow::Result<Expr> {
    let mut expr = self.parse_and()?;
    while self.consume(&Token::OrOr) {
      let right = self.parse_and()?;
      expr = Expr::Binary(Box::new(expr), BinaryOp::Or, Box::new(right));
    }
    Ok(expr)
  }

  fn parse_and(&mut self) -> anyhow::Result<Expr> {
    let mut expr = self.parse_equality()?;
    while self.consume(&Token::AndAnd) {
      let right = self.parse_equality()?;
      expr = Expr::Binary(Box::new(expr), BinaryOp::And, Box::new(right));
    }
    Ok(expr)
  }

  fn parse_equality(&mut self) -> anyhow::Result<Expr> {
    let mut expr = self.parse_comparison()?;
    loop {
      let op = if self.consume(&Token::EqEq) {
        Some(BinaryOp::Eq)
      } else if self.consume(&Token::Ne) {
        Some(BinaryOp::Ne)
      } else {
        None
      };
      let Some(op) = op else {
        break;
      };
      let right = self.parse_comparison()?;
      expr = Expr::Binary(Box::new(expr), op, Box::new(right));
    }
    Ok(expr)
  }

  fn parse_comparison(&mut self) -> anyhow::Result<Expr> {
    let mut expr = self.parse_additive()?;
    loop {
      let op = if self.consume(&Token::Lt) {
        Some(BinaryOp::Lt)
      } else if self.consume(&Token::Le) {
        Some(BinaryOp::Le)
      } else if self.consume(&Token::Gt) {
        Some(BinaryOp::Gt)
      } else if self.consume(&Token::Ge) {
        Some(BinaryOp::Ge)
      } else {
        None
      };
      let Some(op) = op else {
        break;
      };
      let right = self.parse_additive()?;
      expr = Expr::Binary(Box::new(expr), op, Box::new(right));
    }
    Ok(expr)
  }

  fn parse_additive(&mut self) -> anyhow::Result<Expr> {
    let mut expr = self.parse_unary()?;
    while self.consume(&Token::Plus) {
      let right = self.parse_unary()?;
      expr = Expr::Binary(Box::new(expr), BinaryOp::Add, Box::new(right));
    }
    Ok(expr)
  }

  fn parse_unary(&mut self) -> anyhow::Result<Expr> {
    if self.consume(&Token::Bang) {
      return Ok(Expr::UnaryNot(Box::new(self.parse_unary()?)));
    }
    self.parse_postfix()
  }

  fn parse_postfix(&mut self) -> anyhow::Result<Expr> {
    let mut expr = self.parse_primary()?;
    while self.consume(&Token::Dot) {
      let field = self.expect_ident()?;
      if self.consume(&Token::LParen) {
        let args = self.parse_args()?;
        expr = Expr::Call(Box::new(expr), field, args);
      } else {
        expr = Expr::Member(Box::new(expr), field);
      }
    }
    Ok(expr)
  }

  fn parse_primary(&mut self) -> anyhow::Result<Expr> {
    match self.advance() {
      Token::True => Ok(Expr::Bool(true)),
      Token::False => Ok(Expr::Bool(false)),
      Token::Null => Ok(Expr::Null),
      Token::Int(value) => Ok(Expr::Int(value)),
      Token::String(value) => Ok(Expr::String(value)),
      Token::Ident(value) => {
        validate_identifier(&value)?;
        Ok(Expr::Ident(value))
      }
      Token::LParen => {
        let expr = self.parse_or()?;
        self.expect(Token::RParen)?;
        Ok(expr)
      }
      token => bail!("unexpected token {:?}", token),
    }
  }

  fn parse_args(&mut self) -> anyhow::Result<Vec<Expr>> {
    let mut args = Vec::new();
    if self.consume(&Token::RParen) {
      return Ok(args);
    }
    loop {
      args.push(self.parse_or()?);
      if self.consume(&Token::RParen) {
        break;
      }
      self.expect(Token::Comma)?;
    }
    Ok(args)
  }

  fn expect_ident(&mut self) -> anyhow::Result<String> {
    match self.advance() {
      Token::Ident(value) => {
        validate_identifier(&value)?;
        Ok(value)
      }
      token => bail!("expected identifier, got {:?}", token),
    }
  }

  fn expect(&mut self, expected: Token) -> anyhow::Result<()> {
    let token = self.advance();
    if token == expected {
      Ok(())
    } else {
      bail!("expected {:?}, got {:?}", expected, token)
    }
  }

  fn consume(&mut self, expected: &Token) -> bool {
    if self.peek() == expected {
      self.position += 1;
      true
    } else {
      false
    }
  }

  fn advance(&mut self) -> Token {
    let token = self.peek().clone();
    if !matches!(token, Token::Eof) {
      self.position += 1;
    }
    token
  }

  fn peek(&self) -> &Token {
    self.tokens.get(self.position).unwrap_or(&Token::Eof)
  }
}

fn tokenize(input: &str) -> Vec<Token> {
  let mut chars = input.chars().peekable();
  let mut tokens = Vec::new();

  while let Some(ch) = chars.next() {
    match ch {
      ch if ch.is_whitespace() => {}
      '\'' => {
        let mut value = String::new();
        while let Some(next) = chars.next() {
          match next {
            '\\' => {
              if let Some(escaped) = chars.next() {
                value.push(escaped);
              }
            }
            '\'' => break,
            other => value.push(other),
          }
        }
        tokens.push(Token::String(value));
      }
      '0'..='9' => {
        let mut value = ch.to_string();
        while let Some(next) = chars.peek() {
          if next.is_ascii_digit() {
            value.push(chars.next().unwrap_or_default());
          } else {
            break;
          }
        }
        tokens.push(Token::Int(value.parse().unwrap_or_default()));
      }
      'A'..='Z' | 'a'..='z' | '_' => {
        let mut value = ch.to_string();
        while let Some(next) = chars.peek() {
          if next.is_ascii_alphanumeric() || *next == '_' {
            value.push(chars.next().unwrap_or_default());
          } else {
            break;
          }
        }
        tokens.push(match value.as_str() {
          "true" => Token::True,
          "false" => Token::False,
          "null" => Token::Null,
          _ => Token::Ident(value),
        });
      }
      '.' => tokens.push(Token::Dot),
      ',' => tokens.push(Token::Comma),
      '(' => tokens.push(Token::LParen),
      ')' => tokens.push(Token::RParen),
      '+' => tokens.push(Token::Plus),
      '!' if chars.peek() == Some(&'=') => {
        chars.next();
        tokens.push(Token::Ne);
      }
      '!' => tokens.push(Token::Bang),
      '=' if chars.peek() == Some(&'=') => {
        chars.next();
        tokens.push(Token::EqEq);
      }
      '<' if chars.peek() == Some(&'=') => {
        chars.next();
        tokens.push(Token::Le);
      }
      '<' => tokens.push(Token::Lt),
      '>' if chars.peek() == Some(&'=') => {
        chars.next();
        tokens.push(Token::Ge);
      }
      '>' => tokens.push(Token::Gt),
      '&' if chars.peek() == Some(&'&') => {
        chars.next();
        tokens.push(Token::AndAnd);
      }
      '|' if chars.peek() == Some(&'|') => {
        chars.next();
        tokens.push(Token::OrOr);
      }
      _ => tokens.push(Token::Invalid(ch)),
    }
  }

  tokens.push(Token::Eof);
  tokens
}

fn validate_identifier(identifier: &str) -> anyhow::Result<()> {
  match identifier {
    "if" | "else" | "for" | "while" | "do" | "switch" | "let" | "const" | "function" | "import"
    | "export" | "new" | "try" | "catch" | "throw" | "await" | "return" => {
      bail!("forbidden OxiRule construct {identifier}")
    }
    _ => Ok(()),
  }
}
