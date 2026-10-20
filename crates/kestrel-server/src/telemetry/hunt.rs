//! Hunt filter expressions → parameterised SQL.
//!
//! Grammar (case-insensitive keywords):
//! ```text
//! expr    := and_expr ("or" and_expr)*
//! and_expr:= term ("and" term)*
//! term    := "(" expr ")" | field op value
//! op      := "=" | "!=" | "~" | ">" | "<"
//! value   := "quoted string" | 'quoted string' | bare-word | number
//! ```
//! Field names come from a strict allow-list and map to fixed column
//! expressions. Values are never interpolated into SQL: they become bind
//! parameters (`$n` for Postgres, `{pN:Type}` for ClickHouse).

use std::fmt;

pub const MAX_CLAUSES: usize = 32;
pub const MAX_VALUE_LEN: usize = 1024;
pub const MAX_QUERY_LEN: usize = 8192;
const MAX_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    EventType,
    Image,
    Cmdline,
    FilePath,
    DstIp,
    DstPort,
    DnsQname,
    Signer,
    Sha256,
    User,
    Hostname,
    DeviceId,
    RegKey,
    RegValue,
    TargetImage,
    GrantedAccess,
    ReturnCode,
    EventOp,
    NewExt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    Str,
    Num,
    Uuid,
}

impl Field {
    pub fn parse(name: &str) -> Option<Field> {
        Some(match name.to_ascii_lowercase().as_str() {
            "event_type" => Field::EventType,
            "image" => Field::Image,
            "cmdline" => Field::Cmdline,
            "file_path" => Field::FilePath,
            "dst_ip" => Field::DstIp,
            "dst_port" => Field::DstPort,
            "dns_qname" => Field::DnsQname,
            "signer" => Field::Signer,
            "sha256" => Field::Sha256,
            "user" => Field::User,
            "hostname" => Field::Hostname,
            "device_id" => Field::DeviceId,
            "reg_key" => Field::RegKey,
            "reg_value" => Field::RegValue,
            "target_image" => Field::TargetImage,
            "granted_access" => Field::GrantedAccess,
            "return_code" => Field::ReturnCode,
            "op" => Field::EventOp,
            "new_ext" => Field::NewExt,
            _ => return None,
        })
    }

    pub fn names() -> &'static [&'static str] {
        &[
            "event_type",
            "image",
            "cmdline",
            "file_path",
            "dst_ip",
            "dst_port",
            "dns_qname",
            "signer",
            "sha256",
            "user",
            "hostname",
            "device_id",
            "reg_key",
            "reg_value",
            "target_image",
            "granted_access",
            "return_code",
            "op",
            "new_ext",
        ]
    }

    /// Field name as typed in queries (used in error messages).
    pub fn column(&self) -> &'static str {
        match self {
            Field::EventType => "event_type",
            Field::Image => "image",
            Field::Cmdline => "cmdline",
            Field::FilePath => "file_path",
            Field::DstIp => "dst_ip",
            Field::DstPort => "dst_port",
            Field::DnsQname => "dns_qname",
            Field::Signer => "signer",
            Field::Sha256 => "sha256",
            Field::User => "user_name",
            Field::Hostname => "hostname",
            Field::DeviceId => "device_id",
            Field::RegKey => "reg_key",
            Field::RegValue => "reg_value",
            Field::TargetImage => "target_image",
            Field::GrantedAccess => "granted_access",
            Field::ReturnCode => "return_code",
            Field::EventOp => "op",
            Field::NewExt => "new_ext",
        }
    }

    /// Fixed SQL expression for the field in one backend. Most fields are
    /// plain columns shared by both `events` tables; the rest are read from
    /// the stored event JSON (`raw`) where a backend has no column for them.
    /// Never contains user input.
    pub fn sql(&self, d: Dialect) -> &'static str {
        match (self, d) {
            (Field::User, _) => "user_name",
            (Field::EventOp, _) => "file_op",
            (Field::RegValue, Dialect::ClickHouse) => "reg_value",
            (Field::RegValue, Dialect::Postgres) => "coalesce(raw->>'value_name', '')",
            (Field::GrantedAccess, Dialect::ClickHouse) => "granted_access",
            (Field::GrantedAccess, Dialect::Postgres) => {
                "(CASE WHEN jsonb_typeof(raw->'granted_access') = 'number' THEN (raw->>'granted_access')::bigint ELSE 0 END)"
            }
            (Field::ReturnCode, Dialect::ClickHouse) => "JSONExtractUInt(raw, 'return_code')",
            (Field::ReturnCode, Dialect::Postgres) => {
                "(CASE WHEN jsonb_typeof(raw->'return_code') = 'number' THEN (raw->>'return_code')::bigint ELSE 0 END)"
            }
            (Field::NewExt, Dialect::ClickHouse) => "JSONExtractString(raw, 'top_new_ext')",
            (Field::NewExt, Dialect::Postgres) => "coalesce(raw->>'top_new_ext', '')",
            (f, _) => f.column(),
        }
    }

    pub fn ty(&self) -> FieldType {
        match self {
            Field::DstPort | Field::GrantedAccess | Field::ReturnCode => FieldType::Num,
            Field::DeviceId => FieldType::Uuid,
            _ => FieldType::Str,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Contains,
    Gt,
    Lt,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Cmp { field: Field, op: Op, value: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Op(Op),
    And,
    Or,
    LParen,
    RParen,
}

fn tokenize(s: &str) -> Result<Vec<Tok>, ParseError> {
    if s.len() > MAX_QUERY_LEN {
        return Err(ParseError(format!(
            "query longer than {MAX_QUERY_LEN} characters"
        )));
    }
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = vec![];
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '=' => {
                out.push(Tok::Op(Op::Eq));
                i += 1;
                // tolerate "=="
                if i < chars.len() && chars[i] == '=' {
                    i += 1;
                }
            }
            '!' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    out.push(Tok::Op(Op::Ne));
                    i += 2;
                } else {
                    return Err(ParseError("expected '!='".into()));
                }
            }
            '~' => {
                out.push(Tok::Op(Op::Contains));
                i += 1;
            }
            '>' => {
                out.push(Tok::Op(Op::Gt));
                i += 1;
            }
            '<' => {
                out.push(Tok::Op(Op::Lt));
                i += 1;
            }
            '"' | '\'' => {
                let quote = c;
                i += 1;
                let mut v = String::new();
                let mut closed = false;
                while i < chars.len() {
                    let ch = chars[i];
                    if ch == '\\'
                        && i + 1 < chars.len()
                        && (chars[i + 1] == quote || chars[i + 1] == '\\')
                    {
                        v.push(chars[i + 1]);
                        i += 2;
                        continue;
                    }
                    if ch == quote {
                        closed = true;
                        i += 1;
                        break;
                    }
                    v.push(ch);
                    i += 1;
                }
                if !closed {
                    return Err(ParseError("unterminated string".into()));
                }
                out.push(Tok::Str(v));
            }
            _ => {
                let start = i;
                while i < chars.len() {
                    let ch = chars[i];
                    if ch.is_whitespace()
                        || matches!(ch, '(' | ')' | '=' | '!' | '~' | '>' | '<' | '"' | '\'')
                    {
                        break;
                    }
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                match word.to_ascii_lowercase().as_str() {
                    "and" | "&&" => out.push(Tok::And),
                    "or" | "||" => out.push(Tok::Or),
                    _ => out.push(Tok::Ident(word)),
                }
            }
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
    clauses: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }
    fn expr(&mut self, depth: usize) -> Result<Expr, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError("expression nested too deeply".into()));
        }
        let mut left = self.and_expr(depth)?;
        while self.peek() == Some(&Tok::Or) {
            self.next();
            let right = self.and_expr(depth)?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }
    fn and_expr(&mut self, depth: usize) -> Result<Expr, ParseError> {
        let mut left = self.term(depth)?;
        while self.peek() == Some(&Tok::And) {
            self.next();
            let right = self.term(depth)?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }
    fn term(&mut self, depth: usize) -> Result<Expr, ParseError> {
        match self.next() {
            Some(Tok::LParen) => {
                let e = self.expr(depth + 1)?;
                match self.next() {
                    Some(Tok::RParen) => Ok(e),
                    _ => Err(ParseError("expected ')'".into())),
                }
            }
            Some(Tok::Ident(name)) => {
                let field = Field::parse(&name).ok_or_else(|| {
                    ParseError(format!(
                        "unknown field '{}'; allowed: {}",
                        truncate(&name),
                        Field::names().join(", ")
                    ))
                })?;
                let op = match self.next() {
                    Some(Tok::Op(op)) => op,
                    _ => {
                        return Err(ParseError(format!(
                            "expected operator after '{}'",
                            field.column()
                        )))
                    }
                };
                let value = match self.next() {
                    Some(Tok::Str(v)) | Some(Tok::Ident(v)) => v,
                    _ => return Err(ParseError("expected value".into())),
                };
                if value.len() > MAX_VALUE_LEN {
                    return Err(ParseError(format!(
                        "value longer than {MAX_VALUE_LEN} characters"
                    )));
                }
                if value.contains('\0') {
                    return Err(ParseError("value contains NUL".into()));
                }
                match (field.ty(), op) {
                    (FieldType::Num, _) => {
                        parse_num(&value).ok_or_else(|| {
                            ParseError(format!("{} expects a number", field.column()))
                        })?;
                        if op == Op::Contains {
                            return Err(ParseError(format!(
                                "'~' is not valid for numeric field {}",
                                field.column()
                            )));
                        }
                    }
                    (_, Op::Gt) | (_, Op::Lt) => {
                        return Err(ParseError(
                            "'>'/'<' only apply to numeric fields (dst_port, granted_access, return_code)".into(),
                        ));
                    }
                    (FieldType::Uuid, Op::Contains) => {
                        return Err(ParseError("'~' is not valid for device_id".into()));
                    }
                    (FieldType::Uuid, _) => {
                        uuid::Uuid::parse_str(&value)
                            .map_err(|_| ParseError("device_id expects a UUID".into()))?;
                    }
                    _ => {}
                }
                self.clauses += 1;
                if self.clauses > MAX_CLAUSES {
                    return Err(ParseError(format!("more than {MAX_CLAUSES} conditions")));
                }
                Ok(Expr::Cmp { field, op, value })
            }
            Some(t) => Err(ParseError(format!("unexpected token {t:?}"))),
            None => Err(ParseError("unexpected end of query".into())),
        }
    }
}

fn truncate(s: &str) -> String {
    s.chars().take(64).collect()
}

/// Parse a hunt expression. Empty input → `Ok(None)` (match everything).
pub fn parse(q: &str) -> Result<Option<Expr>, ParseError> {
    let toks = tokenize(q)?;
    if toks.is_empty() {
        return Ok(None);
    }
    let mut p = Parser {
        toks,
        pos: 0,
        clauses: 0,
    };
    let e = p.expr(0)?;
    if p.pos < p.toks.len() {
        return Err(ParseError(format!(
            "unexpected trailing input at token {}",
            p.pos + 1
        )));
    }
    Ok(Some(e))
}

/// Bound parameter value.
#[derive(Clone, Debug, PartialEq)]
pub enum Param {
    Str(String),
    Int(i64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Postgres,
    ClickHouse,
}

/// Accumulates bind parameters while rendering SQL for one dialect.
pub struct SqlParams {
    pub dialect: Dialect,
    pub params: Vec<Param>,
    /// Postgres placeholder offset (number of params bound before this builder).
    pub pg_offset: usize,
}

impl SqlParams {
    pub fn new(dialect: Dialect, pg_offset: usize) -> SqlParams {
        SqlParams {
            dialect,
            params: vec![],
            pg_offset,
        }
    }

    /// Register a parameter and return its placeholder.
    pub fn push(&mut self, p: Param) -> String {
        self.params.push(p.clone());
        let n = self.params.len();
        match self.dialect {
            Dialect::Postgres => format!("${}", n + self.pg_offset),
            Dialect::ClickHouse => {
                let ty = match p {
                    Param::Str(_) => "String",
                    Param::Int(_) => "Int64",
                };
                format!("{{p{n}:{ty}}}")
            }
        }
    }
}

/// Decimal or `0x`-prefixed hexadecimal (access masks, NTSTATUS codes).
pub fn parse_num(v: &str) -> Option<i64> {
    let t = v.trim();
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => i64::from_str_radix(h, 16).ok(),
        None => t.parse::<i64>().ok(),
    }
}

/// Render an expression into a SQL boolean expression.
pub fn render(e: &Expr, sp: &mut SqlParams) -> String {
    match e {
        Expr::And(a, b) => format!("({} AND {})", render(a, sp), render(b, sp)),
        Expr::Or(a, b) => format!("({} OR {})", render(a, sp), render(b, sp)),
        Expr::Cmp { field, op, value } => {
            let col = field.sql(sp.dialect);
            match field.ty() {
                FieldType::Num => {
                    let v = parse_num(value).unwrap_or(0);
                    let ph = sp.push(Param::Int(v));
                    let o = match op {
                        Op::Eq => "=",
                        Op::Ne => "!=",
                        Op::Gt => ">",
                        Op::Lt => "<",
                        Op::Contains => "=",
                    };
                    format!("{col} {o} {ph}")
                }
                FieldType::Uuid => {
                    let ph = sp.push(Param::Str(value.to_ascii_lowercase()));
                    let lhs = match sp.dialect {
                        Dialect::Postgres => format!("{col}::text"),
                        Dialect::ClickHouse => format!("toString({col})"),
                    };
                    let o = if *op == Op::Ne { "!=" } else { "=" };
                    format!("{lhs} {o} {ph}")
                }
                FieldType::Str => {
                    let ph = sp.push(Param::Str(value.clone()));
                    match (sp.dialect, op) {
                        (Dialect::Postgres, Op::Contains) => {
                            format!("strpos(lower({col}), lower({ph})) > 0")
                        }
                        (Dialect::ClickHouse, Op::Contains) => {
                            format!("positionCaseInsensitiveUTF8({col}, {ph}) > 0")
                        }
                        (Dialect::Postgres, Op::Ne) => format!("lower({col}) != lower({ph})"),
                        (Dialect::ClickHouse, Op::Ne) => {
                            format!("lowerUTF8({col}) != lowerUTF8({ph})")
                        }
                        (Dialect::Postgres, _) => format!("lower({col}) = lower({ph})"),
                        (Dialect::ClickHouse, _) => format!("lowerUTF8({col}) = lowerUTF8({ph})"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pg(q: &str) -> (String, Vec<Param>) {
        let e = parse(q).unwrap().unwrap();
        let mut sp = SqlParams::new(Dialect::Postgres, 0);
        let s = render(&e, &mut sp);
        (s, sp.params)
    }

    #[test]
    fn precedence_and_params() {
        let (sql, params) =
            pg(r#"image ~ "powershell" and dst_port > 1024 or event_type = dns_query"#);
        assert_eq!(
            sql,
            "((strpos(lower(image), lower($1)) > 0 AND dst_port > $2) OR lower(event_type) = lower($3))"
        );
        assert_eq!(
            params,
            vec![
                Param::Str("powershell".into()),
                Param::Int(1024),
                Param::Str("dns_query".into())
            ]
        );
    }

    #[test]
    fn clickhouse_placeholders() {
        let e = parse(
            "signer != 'Microsoft Windows' and device_id = 6F9619FF-8B86-D011-B42D-00C04FC964FF",
        )
        .unwrap()
        .unwrap();
        let mut sp = SqlParams::new(Dialect::ClickHouse, 0);
        let s = render(&e, &mut sp);
        assert_eq!(
            s,
            "(lowerUTF8(signer) != lowerUTF8({p1:String}) AND toString(device_id) = {p2:String})"
        );
        assert_eq!(
            sp.params[1],
            Param::Str("6f9619ff-8b86-d011-b42d-00c04fc964ff".into())
        );
    }

    #[test]
    fn injection_attempts_stay_in_params() {
        for q in [
            r#"image = "x' OR 1=1 --""#,
            r#"cmdline ~ "'); DROP TABLE events; --""#,
            r#"image = "a\"b" "#,
            "image = x;DROP",
        ] {
            let (sql, params) = pg(q);
            assert!(!sql.contains("DROP"), "{sql}");
            assert!(!sql.contains("OR 1=1"), "{sql}");
            assert_eq!(params.len(), 1);
        }
        // Unknown fields / raw SQL never reach the renderer.
        assert!(parse("1=1").is_err());
        assert!(parse("image = 'a' ; drop table events").is_err());
        assert!(parse("raw = 'x'").is_err());
        assert!(parse("image = 'a') or (1").is_err());
        assert!(parse("dst_port > '1 or 1=1'").is_err());
        assert!(parse("dst_port ~ 4").is_err());
        assert!(parse("image > 4").is_err());
        assert!(parse("device_id = 'x'' or ''1''=''1'").is_err());
        assert!(parse("image = \"unterminated").is_err());
    }

    #[test]
    fn limits() {
        let long = (0..40)
            .map(|i| format!("image = a{i}"))
            .collect::<Vec<_>>()
            .join(" or ");
        assert!(parse(&long).is_err());
        let deep = format!("{}image = a{}", "(".repeat(20), ")".repeat(20));
        assert!(parse(&deep).is_err());
        assert_eq!(parse("   ").unwrap(), None);
    }

    #[test]
    fn parentheses() {
        let (sql, _) = pg("(image ~ a or image ~ b) and user = bob");
        assert!(
            sql.starts_with(
                "((strpos(lower(image), lower($1)) > 0 OR strpos(lower(image), lower($2)) > 0) AND"
            ),
            "{sql}"
        );
    }

    #[test]
    fn general_malware_fields() {
        let (sql, params) = pg(
            "target_image ~ lsass.exe and granted_access = 0x1fffff and return_code != 0 and reg_value = Debugger and op = delete_value and new_ext = k3str",
        );
        assert!(
            sql.contains("strpos(lower(target_image), lower($1)) > 0"),
            "{sql}"
        );
        assert!(sql.contains("jsonb_typeof(raw->'granted_access')"), "{sql}");
        assert!(sql.contains("raw->>'return_code'"), "{sql}");
        assert!(
            sql.contains("lower(coalesce(raw->>'value_name', '')) = lower($4)"),
            "{sql}"
        );
        assert!(sql.contains("lower(file_op) = lower($5)"), "{sql}");
        assert_eq!(params[1], Param::Int(0x1fffff));
        assert_eq!(params[2], Param::Int(0));
        // The stored JSON itself is not a hunt field.
        assert!(parse("raw ~ x").is_err());
        let e = parse("return_code > 0 and reg_value ~ run")
            .unwrap()
            .unwrap();
        let mut sp = SqlParams::new(Dialect::ClickHouse, 0);
        let ch = render(&e, &mut sp);
        assert!(
            ch.contains("JSONExtractUInt(raw, 'return_code') > {p1:Int64}"),
            "{ch}"
        );
        assert!(
            ch.contains("positionCaseInsensitiveUTF8(reg_value, {p2:String})"),
            "{ch}"
        );
        assert!(parse("granted_access = 0xZZ").is_err());
        assert!(parse("return_code ~ 5").is_err());
    }
}
