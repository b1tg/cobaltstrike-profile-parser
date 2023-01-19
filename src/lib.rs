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
#[derive(Debug, Clone, PartialEq)]
struct OptionSet {
    scope: u8,
    k: String,
    v: String,
}

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

#[derive(Debug, Clone, PartialEq)]
struct OptionLocal {
    scope: String,
    options: Vec<OptionSet>,
}
fn parse_local(input: &str) -> IResult<&str, OptionLocal> {
    let (input, _) = multispace0(input)?;
    let (input, scope) = token(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = tag("{\n")(input)?;
    let (input, options) = many1(parse_line_set)(input)?; // TODO: many0 and many1
    let (input, _) = multispace0(input)?;
    let (input, _) = tag("}\n")(input)?;
    Ok((
        input,
        OptionLocal {
            scope: scope.to_string(),
            options: options,
        },
    ))
}

#[test]
fn test_parse_local() {
    let input = r#"
dns-beacon {
    set maxdns "255";
    set aaaa "bbb";
}
    "#;
    let result = parse_local(input);
    // dbg!(result);
    assert_eq!(
        result.unwrap().1,
        OptionLocal {
            scope: "dns-beacon".to_string(),
            options: [
                OptionSet {
                    scope: 0,
                    k: "maxdns".to_string(),
                    v: "255".to_string(),
                },
                OptionSet {
                    scope: 0,
                    k: "aaaa".to_string(),
                    v: "bbb".to_string(),
                },
            ]
            .to_vec(),
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
    let result = parse_line_set(input);
    dbg!(result);
}
