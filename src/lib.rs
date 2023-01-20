use nom::character::streaming::char;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while, take_while_m_n},
    character::{
        complete::digit1,
        is_alphanumeric,
        streaming::{alphanumeric1, hex_digit1, multispace0},
    },
    combinator::map_res,
    multi::{many0, many1},
    sequence::{preceded, tuple},
    IResult,
};

fn parse_line_set(input: &str) -> IResult<&str, OptionSet> {
    let (input, _) = multispace0(input)?;
    let (input, _) = tag("set ")(input)?;
    let (input, k) = alphanumeric1(input)?;
    let (input, (_, _, v, _)) = tuple((multispace0, tag("\""), alphanumeric1, tag("\"")))(input)?;
    let (input, _) = multispace0(input)?;
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

fn quote_value(i: &str) -> IResult<&str, &str> {
    let (i, (_, res, _)) = tuple((
        tag("\""),
        take_while(|x| is_alphanumeric(x as u8) || b"%.-_=|/();:*\\".contains(&(x as u8))),
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
    opts: Vec<Opt>,
    wrap_actions: WrapActions,
}

fn parse_wrap_block(input: &str) -> IResult<&str, ()> {
    let (input, _) = multispace0(input)?;
    let (input, scope) = token(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = tag("{\n")(input)?;
    let (input, opts) = many1(parse_opt)(input)?; // TODO: many0 and many1
    let (input, wrap_actions) = parse_actions(input)?; // TODO: many0 and many1
                                                       // alt((parse_actions, parse_opt))(input)?;
    let (input, _) = multispace0(input)?;
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
//     let (input, _) = multispace0(input)?;
//     let (input, scope) = token(input)?;
//     let (input, _) = multispace0(input)?;
//     let (input, _) = tag("{\n")(input)?;
//     // let (input, options) = many1(parse_line_set)(input)?; // TODO: many0 and many1
//     alt((parse_line_set, parse))
//     let (input, _) = multispace0(input)?;
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

#[derive(Debug, Clone, PartialEq)]
enum Action {
    base64,
    prepend(String),
    append(String),
    header(String),
    parameter(String),
    print,
}

#[derive(Debug, Clone, PartialEq)]
struct WrapActions {
    name: String, // metadata {}
    actions: Vec<Action>,
}
#[derive(Debug, Clone, PartialEq)]
struct Opt {
    name: String,
    k: String,
    v: String,
}

// header "Accept" "*/*";
// parameter "s" "3717";
fn parse_opt(input: &str) -> IResult<&str, Opt> {
    let (input, _) = multispace0(input)?;
    let (input, name) = token(input)?;
    let (input, _) = multispace0(input)?;
    let (input, (k, _, v)) = tuple((quote_value, tag(" "), quote_value))(input)?; // bad
                                                                                  // dbg!(input, name, k, v);
    let (input, _) = tag(";")(input)?;
    Ok((
        input,
        Opt {
            name: name.to_string(),
            k: k.to_string(),
            v: v.to_string(),
        },
    ))
}

#[test]
fn test_parse_opt() {
    let input = r#"
    header "Host" "www.amazon.com";
    "#;
    let result = parse_opt(input);
    assert_eq!(
        result.unwrap().1,
        Opt {
            name: "header".to_string(),
            k: "Host".to_string(),
            v: "www.amazon.com".to_string(),
        }
    )
}

fn parse_action(input: &str) -> IResult<&str, Action> {
    let (input, _) = multispace0(input)?;
    let (input, k) = token(input)?;
    let (input, _) = multispace0(input)?;
    let (input, value) = alt((quote_value, tag("")))(input)?; // bad
                                                              // dbg!(input, k, value);
    let (input, _) = tag(";")(input)?;
    let action = match k {
        "base64" => Action::base64,
        "prepend" => Action::prepend(value.to_string()),
        "append" => Action::append(value.to_string()),
        "header" => Action::header(value.to_string()),
        "parameter" => Action::parameter(value.to_string()),
        "print" => Action::print,
        _ => unimplemented!(),
    };
    Ok((input, action))
}

#[test]
fn test_parse_action() {
    let input = r#" prepend "session-token=";"#;
    let result = parse_action(input);
    assert_eq!(
        result.unwrap().1,
        Action::prepend("session-token=".to_string())
    );
    let input = r#"       base64;"#;
    let result = parse_action(input);
    assert_eq!(result.unwrap().1, Action::base64);
}

fn parse_actions(input: &str) -> IResult<&str, WrapActions> {
    let (input, _) = multispace0(input)?;
    let (input, scope) = token(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = tag("{\n")(input)?;
    let (input, actions) = many1(parse_action)(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = tag("}\n")(input)?;
    Ok((
        input,
        WrapActions {
            name: scope.to_string(),
            actions: actions,
        },
    ))
}
#[test]
fn test_parse_actions() {
    let input = r#"
    metadata {
        base64;
        prepend "session-token=";
        prepend "skin=noskin;";
        append "csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996";
        header "Cookie";
    }
"#;
    let result = parse_actions(input);
    assert_eq!(
        result.unwrap().1,
        WrapActions {
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
}

// #[test]
// fn test_parse_local1() {
//     let input = r#"
// dns-beacon {
//     set maxdns "255";
//     set aaaa "bbb";
// }
//     "#;
//     let result = parse_local(input);
//     // dbg!(result);
//     assert_eq!(
//         result.unwrap().1,
//         OptionLocal {
//             scope: "dns-beacon".to_string(),
//             options: [
//                 OptionSet {
//                     scope: 0,
//                     k: "maxdns".to_string(),
//                     v: "255".to_string(),
//                 },
//                 OptionSet {
//                     scope: 0,
//                     k: "aaaa".to_string(),
//                     v: "bbb".to_string(),
//                 },
//             ]
//             .to_vec(),
//         }
//     );
// }

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
    let result = parse_line_set(input);
    dbg!(result);
}
