use nom::branch::*;
use nom::bytes::complete::{tag, take};
use nom::character::complete::{alpha1, alphanumeric1, digit1, multispace0};
use nom::combinator::verify;
use nom::combinator::{map, map_res, recognize};
use nom::multi::many0;
use nom::sequence::{delimited, pair, tuple};
use nom::*;
use std::iter::Enumerate;
use std::ops::{Range, RangeFrom, RangeFull, RangeTo};
use std::str;
use std::str::FromStr;
use std::str::Utf8Error;
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum Token {
    LBrace,
    RBrace,
    SemiColon,
    Set,
    Ident(String),
    StringLiteral(String),
    Comment(String),
}
#[derive(Clone, Copy, PartialEq, Debug)]
#[repr(C)]
pub struct Tokens<'a> {
    pub tok: &'a [Token],
    pub start: usize,
    pub end: usize,
}

impl<'a> Tokens<'a> {
    pub fn new(vec: &'a [Token]) -> Self {
        Tokens {
            tok: vec,
            start: 0,
            end: vec.len(),
        }
    }
}

impl<'a> InputLength for Tokens<'a> {
    #[inline]
    fn input_len(&self) -> usize {
        self.tok.len()
    }
}

impl<'a> InputTake for Tokens<'a> {
    #[inline]
    fn take(&self, count: usize) -> Self {
        Tokens {
            tok: &self.tok[0..count],
            start: 0,
            end: count,
        }
    }

    #[inline]
    fn take_split(&self, count: usize) -> (Self, Self) {
        let (prefix, suffix) = self.tok.split_at(count);
        let first = Tokens {
            tok: prefix,
            start: 0,
            end: prefix.len(),
        };
        let second = Tokens {
            tok: suffix,
            start: 0,
            end: suffix.len(),
        };
        (second, first)
    }
}

impl InputLength for Token {
    #[inline]
    fn input_len(&self) -> usize {
        1
    }
}

impl<'a> Slice<Range<usize>> for Tokens<'a> {
    #[inline]
    fn slice(&self, range: Range<usize>) -> Self {
        Tokens {
            tok: self.tok.slice(range.clone()),
            start: self.start + range.start,
            end: self.start + range.end,
        }
    }
}

impl<'a> Slice<RangeTo<usize>> for Tokens<'a> {
    #[inline]
    fn slice(&self, range: RangeTo<usize>) -> Self {
        self.slice(0..range.end)
    }
}

impl<'a> Slice<RangeFrom<usize>> for Tokens<'a> {
    #[inline]
    fn slice(&self, range: RangeFrom<usize>) -> Self {
        self.slice(range.start..self.end - self.start)
    }
}

impl<'a> Slice<RangeFull> for Tokens<'a> {
    #[inline]
    fn slice(&self, _: RangeFull) -> Self {
        Tokens {
            tok: self.tok,
            start: self.start,
            end: self.end,
        }
    }
}

impl<'a> InputIter for Tokens<'a> {
    type Item = &'a Token;
    type Iter = Enumerate<::std::slice::Iter<'a, Token>>;
    type IterElem = ::std::slice::Iter<'a, Token>;

    #[inline]
    fn iter_indices(&self) -> Enumerate<::std::slice::Iter<'a, Token>> {
        self.tok.iter().enumerate()
    }
    #[inline]
    fn iter_elements(&self) -> ::std::slice::Iter<'a, Token> {
        self.tok.iter()
    }
    #[inline]
    fn position<P>(&self, predicate: P) -> Option<usize>
    where
        P: Fn(Self::Item) -> bool,
    {
        self.tok.iter().position(predicate)
    }
    #[inline]
    fn slice_index(&self, count: usize) -> Result<usize, Needed> {
        if self.tok.len() >= count {
            Ok(count)
        } else {
            Err(Needed::Unknown)
        }
    }
}
macro_rules! tag_token (
    ($func_name:ident, $tag: expr) => (
        fn $func_name(tokens: Tokens) -> IResult<Tokens, Tokens> {
            verify(take(1usize), |t: &Tokens| t.tok[0] == $tag)(tokens)
        }
    )
  );

// tag_token!(set_tag, Token::Set);
// tag_token!(assign_tag, Token::Assign);
tag_token!(semicolon_tag, Token::SemiColon);
tag_token!(lbrace_tag, Token::LBrace);
tag_token!(rbrace_tag, Token::RBrace);
use nom::error::{Error, ErrorKind};

fn set_tag(input: Tokens) -> IResult<Tokens, Ident> {
    let (i1, t1) = take(1usize)(input)?;
    // dbg!(i1, t1);
    if t1.tok.is_empty() {
        Err(Err::Error(Error::new(input, ErrorKind::Tag)))
    } else {
        if let Token::Ident(name) = t1.tok[0].clone() {
            if name == "set".to_string() {
                return Ok((i1, Ident(name)));
            }
        }
        return Err(Err::Error(Error::new(input, ErrorKind::Tag)));
        // match t1.tok[0].clone() {
        //     Token::Ident(name) => Ok((i1, Ident(name))),
        //     _ => Err(Err::Error(Error::new(input, ErrorKind::Tag))),
        // }
    }
}

fn parse_ident(input: Tokens) -> IResult<Tokens, Ident> {
    let (i1, t1) = take(1usize)(input)?;
    if t1.tok.is_empty() {
        Err(Err::Error(Error::new(input, ErrorKind::Tag)))
    } else {
        match t1.tok[0].clone() {
            Token::Ident(name) => Ok((i1, Ident(name))),
            _ => Err(Err::Error(Error::new(input, ErrorKind::Tag))),
        }
    }
}
fn parse_str(input: Tokens) -> IResult<Tokens, StringLiteral> {
    let (i1, t1) = take(1usize)(input)?;
    if t1.tok.is_empty() {
        Err(Err::Error(Error::new(input, ErrorKind::Tag)))
    } else {
        match t1.tok[0].clone() {
            Token::StringLiteral(name) => Ok((i1, StringLiteral(name))),
            _ => Err(Err::Error(Error::new(input, ErrorKind::Tag))),
        }
    }
}
macro_rules! syntax {
    ($func_name: ident, $tag_string: literal, $output_token: expr) => {
        fn $func_name<'a>(s: &'a [u8]) -> IResult<&[u8], Token> {
            map(tag($tag_string), |_| $output_token)(s)
        }
    };
}
syntax! {lbrace_punctuation, "{", Token::LBrace}
syntax! {rbrace_punctuation, "}", Token::RBrace}
syntax! {semicolon_punctuation, ";", Token::SemiColon}
syntax! {set_punctuation, "set", Token::Set}
fn convert_vec_utf8(v: Vec<u8>) -> Result<String, Utf8Error> {
    let slice = v.as_slice();
    str::from_utf8(slice).map(|s| s.to_owned())
}
fn concat_slice_vec(c: &[u8], done: Vec<u8>) -> Vec<u8> {
    let mut new_vec = c.to_vec();
    new_vec.extend(&done);
    new_vec
}
fn pis(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    use std::result::Result::*;

    let (i1, c1) = take(1usize)(input)?;
    match c1.as_bytes() {
        b"\"" => Ok((input, vec![])),
        b"\\" => {
            let (i2, c2) = take(1usize)(i1)?;
            pis(i2).map(|(slice, done)| (slice, concat_slice_vec(c2, done)))
        }
        c => pis(i1).map(|(slice, done)| (slice, concat_slice_vec(c, done))),
    }
}
fn string(input: &[u8]) -> IResult<&[u8], String> {
    delimited(tag("\""), map_res(pis, convert_vec_utf8), tag("\""))(input)
}
fn lex_string(input: &[u8]) -> IResult<&[u8], Token> {
    map(string, Token::StringLiteral)(input)
}

use nom::character::streaming::none_of;
use nom::sequence::preceded;

use crate::{token, ProtocolTransaction, RoleIndicator};
fn xxx(input: &[u8]) -> IResult<&[u8], String> {
    let (i, _) = preceded(tag("#"), many0(none_of("\n")))(input)?;
    Ok((i, "".to_string()))
}
fn lex_comment(input: &[u8]) -> IResult<&[u8], Token> {
    map(xxx, Token::Comment)(input)
}

fn complete_byte_slice_str_from_utf8(c: &[u8]) -> Result<&str, Utf8Error> {
    str::from_utf8(c)
}
fn lex_reserved_ident(input: &[u8]) -> IResult<&[u8], Token> {
    map_res(
        recognize(pair(
            alt((alpha1, tag("_"))),
            many0(alt((alphanumeric1, tag("_"), tag("-")))),
        )),
        |s| {
            let c = complete_byte_slice_str_from_utf8(s);
            c.map(|syntax| Token::Ident(syntax.to_string()))
        },
    )(input)
}
fn lex_token(input: &[u8]) -> IResult<&[u8], Token> {
    alt((
        lbrace_punctuation,
        rbrace_punctuation,
        semicolon_punctuation,
        lex_string,
        lex_reserved_ident,
        lex_comment,
    ))(input)
}

fn lex_tokens(input: &[u8]) -> IResult<&[u8], Vec<Token>> {
    many0(delimited(multispace0, lex_token, multispace0))(input)
}

#[test]
fn test_tt() {
    let i = r#"
    set sleeptime "5000";
    set jitter    "0";
    set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";
    dns-beacon {
        set maxdns "255";
    }
    http-get {
        # 11
        # 1111
        set uri "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books"; #fafaf

        client {

            header "Accept" "*/*";
            header "Host" "www.amazon.com";

            metadata {
                base64;
                prepend "session-token=";
                prepend "skin=noskin;";
                append "csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996";
                header "Cookie";
            }
        }

        server {

            header "Server" "Server";
            header "x-amz-id-1" "THKUYEZKCKPGY5T42PZT";
            header "x-amz-id-2" "a21yZ2xrNDNtdGRsa212bGV3YW85amZuZW9ydG5rZmRuZ2tmZGl4aHRvNDVpbgo=";
            header "X-Frame-Options" "SAMEORIGIN";
            header "Content-Encoding" "gzip";

            output {
                print;
            }
        }
    }

    "#
    .as_bytes();
    let i1 = r#"
    client {

        header "Accept" "*/*";
        header "Host" "www.amazon.com";

        metadata {
            base64;
            prepend "session-token=";
            prepend "skin=noskin;";
            append "csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996";
            header "Cookie";
        }
    }

    "#
    .as_bytes();
    let i = include_bytes!("..\\Malleable-C2-Profiles\\APT\\havex.profile"); // ok

    let result = lex_tokens(i).unwrap();
    // dbg!(&result);

    let mut proto_trans = "";
    let mut role_indicator = "";

    let mut i = 0;
    // for token in &result.1 {
    // for i in 0..result.1.len() {
    let mut tokens = result.1;
    tokens.drain_filter(|x| x == &Token::Comment("".to_string()));

    // dbg!(&tokens[0..4]);
    let tokens = Tokens::new(&tokens);
    dbg!(tokens);
    let result = parse_profile(tokens).unwrap();
    // let result = parse_set_kv_stmt(tokens).unwrap();
    dbg!(result.1);
    // loop {
    //     let token = &tokens[i];
    //     match token {
    //         Token::Var(var) => {
    //             if var == &"set" {
    //                 // assert_eq!(tokens[i+3], Token::SemiColon);

    //                 let set_option = SetOption {
    //                     scope: "global".to_string(),
    //                     k: tokens[i+1].1,
    //                     v: tokens[i+1].1
    //                 };
    //                 i+= 3;
    //             }
    //         }
    //         _ => {
    //             unimplemented!()
    //         }
    //     }
    // }
}

// fn parse_set_kv(input: Tokens) -> IResult<Tokens, Expr> {

// }

fn parse_set_stmt(input: Tokens) -> IResult<Tokens, Stmt> {
    map(
        tuple((set_tag, parse_ident, parse_str, semicolon_tag)),
        |(_, ident, expr, _)| Stmt::SetStmt(ident, expr),
    )(input)
}

/// header "Accept" "*/*";
fn parse_set_kv_stmt(input: Tokens) -> IResult<Tokens, Stmt> {
    map(
        tuple((parse_ident, parse_str, parse_str, semicolon_tag)),
        |(ident, k, v, _)| Stmt::SetKVStmt(ident, k, v),
    )(input)
}

/// stringw "%s <%s> (Type=%i, Access=%i, ID='%s')";
fn parse_set_v_stmt(input: Tokens) -> IResult<Tokens, Stmt> {
    map(
        tuple((parse_ident, parse_str, semicolon_tag)),
        |(ident, v, _)| Stmt::SetVStmt(ident, v),
    )(input)
}

// base64;
// prepend "session-token=";
fn parse_action(input: Tokens) -> IResult<Tokens, Stmt> {
    let p1 = map(tuple((parse_ident, semicolon_tag)), |(ident, _)| {
        Stmt::Action(ident, None)
    });
    let p2 = map(
        tuple((parse_ident, parse_str, semicolon_tag)),
        |(ident, s, _)| Stmt::Action(ident, Some(s)),
    );
    alt((p1, p2))(input)
}

// metadata { ... }
fn parse_actions(input: Tokens) -> IResult<Tokens, Stmt> {
    map(
        tuple((parse_ident, lbrace_tag, many0(parse_action), rbrace_tag)),
        |(ident, _, actions, _)| Stmt::Actions(ident, actions),
    )(input)
}

fn parse_role(input: Tokens) -> IResult<Tokens, Stmt> {
    let (input, ident) = parse_ident(input)?;
    let (input, _) = lbrace_tag(input)?;
    let (input, stmts) = many0(alt((parse_set_kv_stmt, parse_actions)))(input)?;
    let (input, _) = rbrace_tag(input)?;
    Ok((input, Stmt::RoleStmt(ident, stmts)))
}

fn parse_protocol_transaction_inner(input: Tokens) -> IResult<Tokens, Vec<Stmt>> {
    many0(alt((parse_set_stmt, parse_role, parse_set_v_stmt)))(input)
}

fn parse_protocol_transaction(input: Tokens) -> IResult<Tokens, Stmt> {
    map(
        tuple((
            parse_ident,
            lbrace_tag,
            parse_protocol_transaction_inner,
            rbrace_tag,
        )),
        |(ident, _, transactions, _)| Stmt::ProtocolStmt(ident, transactions),
    )(input)
}

fn parse_profile(input: Tokens) -> IResult<Tokens, Vec<Stmt>> {
    let (input, stmts) = many0(alt((parse_set_stmt, parse_protocol_transaction)))(input)?;
    Ok((input, stmts))
}

#[test]
fn test_parse_profile() {}

#[derive(Debug, Default, Clone)]
struct SetOption {
    scope: String,
    k: String,
    v: String,
}

// struct
use Token::Set;

pub enum ProtoTransStmt {
    SetStmt(Token, Token),
    RoleIndicatorStmt(RoleIndicator),
    RoleOptStmt,
}
#[derive(PartialEq, Debug, Eq, Clone)]
pub struct Ident(pub String);
#[derive(PartialEq, Debug, Eq, Clone)]
pub struct StringLiteral(pub String);
#[derive(PartialEq, Debug, Eq, Clone)]
pub enum Stmt {
    SetStmt(Ident, StringLiteral),
    SetKVStmt(Ident, StringLiteral, StringLiteral),
    SetVStmt(Ident, StringLiteral),
    ProtoTransStmt,
    ProtocolStmt(Ident, Vec<Stmt>),
    Action(Ident, Option<StringLiteral>),
    Actions(Ident, Vec<Stmt>),
    RoleStmt(Ident, Vec<Stmt>),
}

#[test]
fn test_tokens() {
    use walkdir::WalkDir;
    for entry in WalkDir::new("Malleable-C2-Profiles\\") {
        let entry = entry.unwrap();
        let p = entry.path();
        if p.extension() != Some(std::ffi::OsStr::new("profile")) {
            continue;
        }
        let input = std::fs::read_to_string(p).unwrap();
        // println!("{:?} {:?}", p, p.extension());
        let result = lex_tokens(input.as_bytes()).expect(p.to_str().unwrap());
    }
}
