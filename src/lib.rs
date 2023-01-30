#![feature(drain_filter)]

use std::fs::{read, read_dir};

use nom::bytes::streaming::{escaped, is_not, take_until};
use nom::character::complete::{anychar, multispace1};
use nom::character::streaming::char;
use nom::character::{is_newline, is_space};
use nom::combinator::{map, opt};
use nom::error::ParseError;
use nom::multi::separated_list0;
use nom::sequence::delimited;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while, take_while_m_n},
    character::{
        is_alphanumeric,
        streaming::{alphanumeric1, hex_digit1, multispace0},
    },
    combinator::map_res,
    multi::{many0, many1},
    sequence::{preceded, tuple},
    IResult,
};

mod token;
use token::*;
fn is_token_char(i: char) -> bool {
    is_alphanumeric(i as u8) || b"-_".contains(&(i as u8))
}

#[test]
fn test_is_token_char() {
    assert_eq!(is_token_char('a'), true);
    assert_eq!(is_token_char('-'), true);
    assert_eq!(is_token_char('\n'), false);
}

fn token(i: &str) -> IResult<&str, &str> {
    take_while(is_token_char)(i)
}

fn spaces_origin(i: &str) -> IResult<&str, &str> {
    take_while(|x| is_space(x as u8) || is_newline(x as u8))(i)
}
use nom::character::streaming::none_of;
use nom::Err::{Error, Failure, Incomplete};
// eat from # to line end
fn comment(i: &str) -> IResult<&str, &str> {
    let (i, _) = spaces_origin(i)?;
    let (i, _) = preceded(char('#'), many0(none_of("\n")))(i)?;
    let (i, _) = spaces_origin(i)?;
    return Ok((i, ""));
}

// fn cls(i: &str) -> IResult<&str, &str> {

// }

#[test]
fn test_comment() {
    // dbg!(many0(comment)("\n   # fafaf\n # 123\n fabc {"));
    // dbg!(spaces("\n   # fafaf\n # 123\n fabc {"));
    dbg!(spaces(" aa"));
    // dbg!(comment("fabc {"));
    // dbg!(spaces("   # fafaf\n # 123\n fabc {"));
    // dbg!(many0(alt((comment, spaces_origin)))(" 12#afafaf\n#aaff\n"));
    // dbg!(spaces_origin("\n#aaff\n"));
    // dbg!(comment("#aaff\n"));
    // dbg!(spaces_origin("\n"));
    // dbg!(comment(""));
    // let i = "#afafaf\n#aaff\n";
    // let mut p = alt((spaces_origin, comment));
    // let mut p = comment;
    // let (i, _) = p(i).unwrap();
    // dbg!(i);
    // let (i, _) = p(i).unwrap();
    // dbg!(i);
    // let (i, _) = p(i).unwrap();
    // let (i, _) = p(i).unwrap();
    // let (i, _) = p(i).unwrap();
    // let (i, _) = p(i).unwrap();
    // let (i, _) = p(i).unwrap();
    // let (i, _) = p(i).unwrap();
}

// spaces_and_comment
fn spaces(i: &str) -> IResult<&str, &str> {
    let (i, _) = spaces_origin(i)?;
    if (i.is_empty()) {
        return Ok((i, ""));
    }
    // let (i, _) = comment(i)?;
    let (i, _) = many0(comment)(i)?;
    return Ok((i, ""));
    // let (i, _) = many0(alt((spaces_origin, comment)))(i)?;
    // Ok((i, ""))
    // loop {
    // println!("remain2... {}", i);

    // let (i, (_, _, _, comment)) = tuple((spaces_origin, tag("#"), spaces_origin, take_while(|x: char|(x!='\r' && x != '\n'))))(i)?;
    // let (i, _) = spaces_origin(i)?;

    // println!("remain1... {}", i);
    // if !i.starts_with("#") {
    //     return Ok((i, ""))
    // } else {

    // }
    // }
    // Ok((i, comment))
}
// fn spaces(i: &str) -> IResult<&str, &str> {

//         let (i, _) = many0(space)(i)?;
//         Ok((i, ""))
// }

// fn spaces_and_comment(i: &str) -> IResult<&str, &str> {
//     let (i, _) = many0(alt((comment, spaces)))(i)?;
//     Ok((i, ""))
// }
use std::str::Utf8Error;
fn convert_vec_utf8(v: Vec<u8>) -> Result<String, Utf8Error> {
    let slice = v.as_slice();
    std::str::from_utf8(slice).map(|s| s.to_owned())
}
fn concat_slice_vec(c: &str, done: Vec<u8>) -> Vec<u8> {
    let mut new_vec = c.as_bytes().to_vec();
    new_vec.extend(&done);
    new_vec
}
use nom::bytes::complete::{ take};
use nom::AsBytes;
// use nom::sequence::{delimited};
fn pis(input: &str) -> IResult<&str, Vec<u8>> {
    use std::result::Result::*;

    let (i1, c1) = take(1usize)(input)?;
    match c1 {
        "\"" => Ok((input, vec![])),
        "\\" => {
            let (i2, c2) = take(1usize)(i1)?;
            pis(i2).map(|(slice, done)| (slice, concat_slice_vec(c2, done)))
        }
        c => pis(i1).map(|(slice, done)| (slice, concat_slice_vec(c, done))),
    }
}
fn quote_value(input: &str) -> IResult<&str, String> {
    delimited(tag("\""), map_res(pis, convert_vec_utf8), tag("\""))(input)
}
// current cant handle escape quote in quote
// https://stackoverflow.com/questions/58904604/parsing-single-quoted-string-with-escaped-quotes-with-nom-5
fn quote_value1(i: &str) -> IResult<&str, &str> {
    let esc = escaped(none_of("\\\""), '\\', tag("\""));
    let esc_or_empty = alt((esc, tag("")));
    let (i, (_, res, _)) = tuple((
        tag("\""),
        esc_or_empty,
        // take_while(|x| is_alphanumeric(x as u8) || b" @%.,~@#$^&*-_=|/();:*\\".contains(&(x as u8))),
        // is_not("\""),
        // take
        tag("\""),
    ))(i)?;
    Ok((i, res))
}

#[test]
fn test_quote_value() {
    let result = quote_value(r#""/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books""#);
    assert_eq!(
        result.unwrap().1,
        "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books"
    );
    assert_eq!(quote_value(
            r#""Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko""#
        ).unwrap().1,
        "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
    );
    assert_eq!(quote_value(r#""中文ok""#).unwrap().1, "中文ok");
    // dbg!(quote_value(r#""<!DOCTYPE html><html lang=\"en\" xml:lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:Web=\"http://schemas.live.com/Web/\"><script type=\"text/javascript\">//<![CDATA[si_ST=new Date;//]]></script><head><!--pc--><title>Bing</title><meta content=\"text/html; charset=utf-8\" http-equiv=\"content-type\" /><link href=\"/search?format=rss&amp;q=canary&amp;go=Search&amp;qs=bs&amp;form=QBRE\" rel=\"alternate\" title=\"XML\" type=\"text/xml\" /><link href=\"/search?format=rss&amp;q=canary&amp;go=Search&amp;qs=bs&amp;form=QBRE\" rel=\"alternate\" title=\"RSS\" type=\"application/rss+xml\" /><link href=\"/sa/simg/bing_p_rr_teal_min.ico\" rel=\"shortcut icon\" /><script type=\"text/javascript\">//<![CDATA[""#));
    // TODO:
    // dbg!(quote_value(r#""\\x63\\x02""#));
    dbg!(quote_value(r#""%s <%s> (Type=%i, Access=%i, ID='%s')";"#));
}

#[derive(Debug, Clone, PartialEq)]
struct OptionSet {
    scope: u8,
    k: String,
    v: String,
}
#[derive(Debug, Clone, PartialEq)]
struct OptionLocal {
    scope: String,
    options: Vec<OptionSet>,
    wrap_blocks: Vec<WrapBlock>,
}

#[derive(Debug, Clone, PartialEq)]
struct WrapBlock {
    opts: Vec<IndicatorOpt>,
    wrap_actions: TransformActions,
}

fn parse_wrap_block(input: &str) -> IResult<&str, ()> {
    let (input, _) = spaces(input)?;
    let (input, scope) = token(input)?;
    let (input, _) = spaces(input)?;
    let (input, _) = tag("{\n")(input)?;
    loop {
        let try1 = many1(parse_indicator_set_kv)(input)?;
    }
    let (input, opts) = many1(parse_indicator_set_kv)(input)?;
    let (input, wrap_actions) = parse_transform_actions(input)?;
    // alt((parse_actions, parse_opt))(input)?;
    let (input, _) = spaces(input)?;
    let (input, _) = tag("}\n")(input)?;
    dbg!(&opts, wrap_actions);
    Ok((input, ()))
}

#[test]
fn test_parse_wrap_block() {
    let input = r#"
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
    "#;
    let result = parse_wrap_block(input);
    dbg!(&result);
}

// fn parse_local(input: &str) -> IResult<&str, OptionLocal> {
//     let (input, _) = spaces(input)?;
//     let (input, scope) = token(input)?;
//     let (input, _) = spaces(input)?;
//     let (input, _) = tag("{\n")(input)?;
//     // let (input, options) = many1(parse_line_set)(input)?; // TODO: many0 and many1
//     alt((parse_line_set, parse))
//     let (input, _) = spaces(input)?;
//     let (input, _) = tag("}\n")(input)?;
//     Ok((
//         input,
//         OptionLocal {
//             scope: scope.to_string(),
//             options: options,
//         },
//     ))
// }

#[test]
fn test_parse_local() {
    let input = r#"
http-get {
    set uri "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";
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
}
    "#;
    // let result = parse_local(input);
    // dbg!(result);
}
#[derive(Debug, Clone, PartialEq)]
struct Options1 {
    scope: String, // http-get
    options: Vec<OptionSet>,
}
// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_profile-language.htm#_Toc65482837
#[derive(Debug, Clone, PartialEq)]
enum Action {
    append(String),
    base64,
    base64url,
    mask,
    netbios,
    netbiosu,
    prepend(String),
    // termination statements
    header(String),
    parameter(String),
    print,
    uri_append,
}

#[derive(Debug, Clone, PartialEq, Default)]
struct TransformActions {
    name: String, // metadata {}
    actions: Vec<Action>,
}
#[derive(Debug, Clone, PartialEq, Default)]
struct IndicatorOpt {
    name: String,
    k: String,
    v: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
struct RoleIndicator {
    role: String,
    set_opts: Vec<IndicatorOpt>,
    transforms: Vec<TransformActions>,
    role_opts: Vec<IndicatorOpt>,
}

#[derive(Debug, Clone, PartialEq, Default)]
struct ProtocolTransaction {
    proto: String,
    local_options: Vec<OptionSet>,
    roles: Vec<RoleIndicator>,
}

#[derive(Debug, Clone, PartialEq, Default)]
struct Profile {
    global_options: Vec<OptionSet>,
    transactions: Vec<ProtocolTransaction>,
}

#[derive(Debug, Clone, PartialEq)]
enum opts_or_transforms {
    opt(IndicatorOpt),
    transform(TransformActions),
    role_opt(IndicatorOpt),
}

#[derive(Debug, Clone, PartialEq)]
enum set_option_or_role_indicators {
    set_option(OptionSet),
    role_indicators(RoleIndicator),
}

use nom::{InputLength, Parser};
#[derive(Debug, Clone, PartialEq)]
enum set_option_or_protocol_transaction {
    set(OptionSet),
    protocol(ProtocolTransaction),
}

// fn alt_two<I, O1, O2, E, F1, F2>(
//     f1: F1,
//     f2: F2,
// ) -> impl FnMut(I) -> IResult<I, (Vec<O1>, Vec<O2>), E>
// where
//     I: Clone + InputLength,
//     F1: Parser<I, O1, E>,
//     F2: Parser<I, O2, E>,
//     E: ParseError<I>,
// {

//     let mut o1: Vec<O1> = vec![];
//     let mut o2: Vec<O2> = vec![];
//     Ok((o1, o2))
//     #[derive(Debug, Clone, PartialEq)]
//     enum two_choices {
//         o1(O1),
//         o2(O2),
//     }
//     fn abc()
// }

fn parse_profile(input: &str) -> IResult<&str, Profile> {
    let mut profile = Profile::default();

    // let mut p0 = parse_set_option_local.or(parse_protocol_transaction);
    // let (input, _) = p0(input)?;
    let p1 = map(parse_set_option_local, |x| {
        set_option_or_protocol_transaction::set(x)
    });
    let p2 = map(parse_protocol_transaction, |x| {
        set_option_or_protocol_transaction::protocol(x)
    });
    dbg!(11111);
    let (input, a_or_b_list) = many0(alt((p1, p2)))(input)?;
    dbg!(22222);
    for a_or_b in a_or_b_list {
        match a_or_b {
            set_option_or_protocol_transaction::set(x) => {
                profile.global_options.push(x);
            }
            set_option_or_protocol_transaction::protocol(x) => {
                profile.transactions.push(x);
            }
        }
    }
    let (input, _) = spaces(input)?;
    Ok((input, profile))
}

fn parse_protocol_transaction(input: &str) -> IResult<&str, ProtocolTransaction> {
    println!("parse_protocol_transaction1: {}({})", input, input.len());
    let (input, _) = spaces(input)?; // spaces("\n    ")  Incomplete(Size(1)
    let (input, proto) = token(input)?;
    let (input, _) = spaces(input)?;
    let (input, _) = tag("{\n")(input)?;
    let mut transaction = ProtocolTransaction::default();
    transaction.proto = proto.to_string();
    // let (input, opt_or_transform_list) = many1(parse_indicator_set_kv_or_transform_actions)(input)?;
    let p1 = map(parse_set_option_local, |x| {
        set_option_or_role_indicators::set_option(x)
    });
    let p2 = map(parse_role_indicators, |x| {
        set_option_or_role_indicators::role_indicators(x)
    });

    let (input, a_or_b_list) = many1(alt((p1, p2)))(input)?;
    for a_or_b in a_or_b_list {
        match a_or_b {
            set_option_or_role_indicators::set_option(x) => {
                transaction.local_options.push(x);
            }
            set_option_or_role_indicators::role_indicators(x) => {
                transaction.roles.push(x);
            }
        }
    }
    println!("parse_protocol_transaction2: {}", input);
    let (input, _) = spaces(input)?;
    println!("parse_protocol_transaction3: {}", input);
    let (input, _) = tag("}")(input)?;
    println!("parse_protocol_transaction4: {}", input);
    Ok((input, transaction))
}

fn parse_set_option_local(input: &str) -> IResult<&str, OptionSet> {
    println!("parse_set_option_local: {}({})", input, input.len());
    let (input, _) = spaces(input)?;
    let (input, _) = tag("set")(input)?;
    let (input, _) = spaces(input)?;
    let (input, k) = token(input)?;
    let (input, (_, v)) = tuple((spaces, quote_value))(input)?;
    // let (input, _) = spaces(input)?;
    let (input, _) = tag(";")(input)?;
    Ok((
        input,
        OptionSet {
            scope: 0,
            k: k.to_string(),
            v: v.to_string(),
        },
    ))
}

fn parse_role_indicators(input: &str) -> IResult<&str, RoleIndicator> {
    let (input, _) = spaces(input)?;
    let (input, role) = token(input)?;
    let (input, _) = spaces(input)?;
    let (input, _) = tag("{\n")(input)?;
    let mut role_indicators = RoleIndicator::default();
    role_indicators.role = role.to_string();

    // let (input, opt_or_transform_list) = many1(parse_indicator_set_kv_or_transform_actions)(input)?;
    let p1 = map(parse_indicator_set_kv, |x| opts_or_transforms::opt(x));
    let p2 = map(parse_transform_actions, |x| {
        opts_or_transforms::transform(x)
    });
    let p3 = map(parse_role_set_kv, |x| opts_or_transforms::role_opt(x));
    dbg!(11111);
    let (input, a_or_b_list) = many0(alt((p1, p2, p3)))(input)?;
    dbg!(22222);
    for a_or_b in a_or_b_list {
        match a_or_b {
            // for opt_or_transform in opt_or_transform_list {
            //     match opt_or_transform {
            opts_or_transforms::opt(opt) => {
                role_indicators.set_opts.push(opt);
            }
            opts_or_transforms::transform(transform) => {
                role_indicators.transforms.push(transform);
            }
            opts_or_transforms::role_opt(x) => {
                role_indicators.role_opts.push(x);
            }
        }
    }
    let (input, _) = spaces(input)?;
    let (input, _) = tag("}\n")(input)?;
    Ok((input, role_indicators))
}

// fn parse_protocol_transaction(input: &str) -> IResult<&str, RoleIndicator> {

// }

// helper function
fn parse_set_option_or_role_indicators(
    input: &str,
) -> IResult<&str, set_option_or_role_indicators> {
    let set_kv_result = parse_set_option_local(input);
    if set_kv_result.is_ok() {
        let (input, set_option) = set_kv_result.unwrap();
        return Ok((input, set_option_or_role_indicators::set_option(set_option)));
    }
    let (input, role_indicators) = parse_role_indicators(input)?;
    return Ok((
        input,
        set_option_or_role_indicators::role_indicators(role_indicators),
    ));
}

// helper function
// fn parse_indicator_set_kv_or_transform_actions(input: &str) -> IResult<&str, opts_or_transforms> {
//     let set_kv_result = parse_indicator_set_kv(input);
//     if set_kv_result.is_ok() {
//         let (input, opt) = set_kv_result.unwrap();
//         return Ok((input, opts_or_transforms::opt(opt)));
//     }
//     let (input, transform) = parse_transform_actions(input)?;
//     return Ok((input, opts_or_transforms::transform(transform)));
// }

fn parse_role_set_kv(input: &str) -> IResult<&str, IndicatorOpt> {
    let (input, _) = spaces(input)?;
    let (input, (k, _, v, _)) = tuple((token, spaces, quote_value, spaces))(input)?; // bad
    let (input, _) = tag(";")(input)?;
    Ok((
        input,
        IndicatorOpt {
            name: "role".to_string(),
            k: k.to_string(),
            v: v.to_string(),
        },
    ))
}

#[test]
fn test_parse_role_set_kv() {
    dbg!(parse_role_set_kv(r#"stringw "a+";"#));
}

fn parse_indicator_set_kv(input: &str) -> IResult<&str, IndicatorOpt> {
    let (input, _) = spaces(input)?;
    let (input, name) = token(input)?;
    let (input, _) = spaces(input)?;
    let (input, (k, _, v)) = tuple((quote_value, spaces, quote_value))(input)?; // bad
                                                                                // dbg!(input, name, k, v);
    let (input, _) = tag(";")(input)?;
    Ok((
        input,
        IndicatorOpt {
            name: name.to_string(),
            k: k.to_string(),
            v: v.to_string(),
        },
    ))
}

fn parse_transform_action(input: &str) -> IResult<&str, Action> {
    let (input, _) = spaces(input)?;
    let (input, k) = token(input)?;
    let (input, _) = spaces(input)?;
    let (input, value) = alt((quote_value, map(tag(""), |s:&str|s.to_string())))(input)?; // bad
                                                              // dbg!(input, k, value);
    let (input, _) = tag(";")(input)?;
    let action = match k {
        "base64" => Action::base64,
        "prepend" => Action::prepend(value),
        "append" => Action::append(value),
        "header" => Action::header(value),
        "parameter" => Action::parameter(value),
        "print" => Action::print,
        "base64url" => Action::base64url,
        "netbios" => Action::netbios,
        "uri-append" => Action::uri_append,
        "mask" => Action::mask,
        "netbiosu" => Action::netbiosu,
        _ => unimplemented!("unknow action {}\n", k),
    };
    Ok((input, action))
}

fn parse_transform_actions(input: &str) -> IResult<&str, TransformActions> {
    let (input, _) = spaces(input)?;
    let (input, scope) = token(input)?;
    let (input, _) = spaces(input)?;
    let (input, _) = tag("{\n")(input)?;
    let (input, actions) = many1(parse_transform_action)(input)?;
    let (input, _) = spaces(input)?;
    let (input, _) = tag("}\n")(input)?;
    Ok((
        input,
        TransformActions {
            name: scope.to_string(),
            actions: actions,
        },
    ))
}

#[test]
fn test_parse_transform_action() {
    let input = r#" prepend "session-token=";"#;
    let result = parse_transform_action(input);
    assert_eq!(
        result.unwrap().1,
        Action::prepend("session-token=".to_string())
    );
    let input = r#"       base64;"#;
    let result = parse_transform_action(input);
    assert_eq!(result.unwrap().1, Action::base64);
}
#[test]
fn test_parse_indicator_set_kv() {
    let input = r#"
    header "Host" "www.amazon.com";
    "#;
    let result = parse_indicator_set_kv(input);
    assert_eq!(
        result.unwrap().1,
        IndicatorOpt {
            name: "header".to_string(),
            k: "Host".to_string(),
            v: "www.amazon.com".to_string(),
        }
    );
    let input = r#"
    parameter "sz" "160x600";
    "#;
    let result = parse_indicator_set_kv(input);
    assert_eq!(
        result.unwrap().1,
        IndicatorOpt {
            name: "parameter".to_string(),
            k: "sz".to_string(),
            v: "160x600".to_string(),
        }
    );
    dbg!(parse_indicator_set_kv(r#"strrep "sz"   "sz";"#));
}
#[test]
fn test_parse_transform_actions() {
    let input = r#"
    metadata {
        base64;
        prepend "session-token=";
        prepend "skin=noskin;";
        append "csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996";
        header "Cookie";
    }
"#;
    let result = parse_transform_actions(input);
    assert_eq!(
        result.unwrap().1,
        TransformActions {
            name: "metadata".to_string(),
            actions: [
                Action::base64,
                Action::prepend("session-token=".to_string(),),
                Action::prepend("skin=noskin;".to_string(),),
                Action::append("csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996".to_string(),),
                Action::header("Cookie".to_string(),),
            ]
            .to_vec()
        }
    );
    let input = r#"
    output {
        base64;
        print;
    }
    "#;
    let result = parse_transform_actions(input);
    assert_eq!(
        result.unwrap().1,
        TransformActions {
            name: "output".to_string(),
            actions: [Action::base64, Action::print,].to_vec(),
        }
    );
}

#[test]
fn test_parse_line_set() {
    let input = r#"
set sleeptime "5000";
set jitter    "0";
set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";

# Updated for 4.3
dns-beacon {
    set maxdns "255";
}
    "#;
    // dbg!(spaces(input));
    // let (input, (_, v)) = tuple((spaces, quote_value))(" \"5000\";").unwrap();
    // let (input, _) = spaces(" \"5000\";").unwrap();
    // dbg!(input);
    // let result = many0(parse_set_option_local)(input);
    // dbg!(result);
    dbg!(parse_set_option_local(
        r#"set rich_header    "\x63\x02\x25\x0f\x27\x63\x4b\x5c\x27\x63\x4b\x5c\x27\x63\x4b\x5c\x9a\x2c\xdd\x5c\x24\x63\x4b\x5c\x2e\x1b\xde\x5c\x3b\x63\x4b\x5c\x2e\x1b\xcf\x5c\x1b\x63\x4b\x5c\x2e\x1b\xc8\x5c\x8f\x63\x4b\x5c\x00\xa5\x30\x5c\x28\x63\x4b\x5c\x27\x63\x4a\x5c\x97\x63\x4b\x5c\x2e\x1b\xc1\x5c\x60\x63\x4b\x5c\x2e\x1b\xd9\x5c\x26\x63\x4b\x5c\x39\x31\xdf\x5c\x26\x63\x4b\x5c\x2e\x1b\xda\x5c\x26\x63\x4b\x5c\x52\x69\x63\x68\x27\x63\x4b\x5c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    "#
    ));
}

#[test]
fn test_parse_role_indicators() {
    let input = r#"
    client {

        header "Accept" "*/*";
        header "Content-Type" "text/xml";
        header "X-Requested-With" "XMLHttpRequest";
        header "Host" "www.amazon.com";

        parameter "sz" "160x600";
        parameter "oe" "oe=ISO-8859-1;";

        id {
            parameter "sn";
        }

        parameter "s" "3717";
        parameter "dc_ref" "http%3A%2F%2Fwww.amazon.com";

        output {
            base64;
            print;
        }
    }

    "#;
    let result = parse_role_indicators(input);
    // dbg!(result);
}

#[test]
fn test_123() {
    let input = r#"

    "#;
    // let a = parse_protocol_transaction(input);
    // dbg!(a);
    dbg!(parse_profile(""));
}

#[test]
fn test_parse_malleable_c2_profiles() {
    use walkdir::WalkDir;
    for entry in WalkDir::new("Malleable-C2-Profiles\\") {
        let entry = entry.unwrap();
        let p = entry.path();
        // println!("{:?} {:?}", p,  p.extension());
        if p.extension() != Some(std::ffi::OsStr::new("profile")) {
            continue;
        }
        let input = std::fs::read_to_string(p).unwrap();
        let input = input.replace("\r\n", "\n");
        let _ = parse_profile(&input).expect(p.to_str().unwrap());
    }
}

#[test]
fn test_parse_profile() {
    // let input = include_str!("..\\Malleable-C2-Profiles\\normal\\bingsearch_getonly.profile"); // ok
    let input = include_str!("..\\Malleable-C2-Profiles\\APT\\havex.profile"); // ok
    let input = input.replace("\r\n", "\n");
    let input = input.replace("\t", "    ");
    let result = parse_profile(&input);
    dbg!(result);
}

#[test]
fn test_parse_profile1() {
    let input = r#"
    "#;
    let input = include_str!("..\\amazon.profile");
    let input = input.replace("\r\n", "\n");
    // let input = include_str!("..\\Malleable-C2-Profiles\\normal\\bingsearch_getonly.profile");
    let result = parse_profile(&input);
    // dbg!(result);
}

#[test]
fn TODO_test11() {
    let res = multispace1::<&str, ()>("\n    1");
    let res = spaces("");
    dbg!(res);
}
