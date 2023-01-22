use nom::character::complete::multispace1;
use nom::character::streaming::char;
use nom::character::{is_newline, is_space};
use nom::combinator::map;
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

fn spaces(i: &str) -> IResult<&str, &str> {
    take_while(|x| is_space(x as u8) || is_newline(x as u8))(i)
}

fn quote_value(i: &str) -> IResult<&str, &str> {
    let (i, (_, res, _)) = tuple((
        tag("\""),
        take_while(|x| is_alphanumeric(x as u8) || b" %.-_=|/();:*\\".contains(&(x as u8))),
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
    dbg!(quote_value(
        r#""Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko""#
    ));
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

#[derive(Debug, Clone, PartialEq)]
enum Action {
    base64,
    prepend(String),
    append(String),
    header(String),
    parameter(String),
    print,
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
}

#[derive(Debug, Clone, PartialEq)]
enum set_option_or_role_indicators {
    set_option(OptionSet),
    role_indicators(RoleIndicator),
}

#[derive(Debug, Clone, PartialEq)]
enum set_option_or_protocol_transaction {
    set(OptionSet),
    protocol(ProtocolTransaction),
}

fn parse_profile(input: &str) -> IResult<&str, Profile> {
    let mut profile = Profile::default();
    let p1 = map(parse_set_option_local, |x| {
        set_option_or_protocol_transaction::set(x)
    });
    let p2 = map(parse_protocol_transaction, |x| {
        set_option_or_protocol_transaction::protocol(x)
    });
    let (input, a_or_b_list) = many0(alt((p1, p2)))(input)?;
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
    let (input, _) = spaces(input)?;
    let (input, _) = tag("}\n")(input)?;
    Ok((input, transaction))
}

fn parse_set_option_local(input: &str) -> IResult<&str, OptionSet> {
    let (input, _) = spaces(input)?;
    let (input, _) = tag("set ")(input)?;
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

    let (input, opt_or_transform_list) = many1(parse_indicator_set_kv_or_transform_actions)(input)?;

    for opt_or_transform in opt_or_transform_list {
        match opt_or_transform {
            opts_or_transforms::opt(opt) => {
                role_indicators.set_opts.push(opt);
            }
            opts_or_transforms::transform(transform) => {
                role_indicators.transforms.push(transform);
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
fn parse_indicator_set_kv_or_transform_actions(input: &str) -> IResult<&str, opts_or_transforms> {
    let set_kv_result = parse_indicator_set_kv(input);
    if set_kv_result.is_ok() {
        let (input, opt) = set_kv_result.unwrap();
        return Ok((input, opts_or_transforms::opt(opt)));
    }
    let (input, transform) = parse_transform_actions(input)?;
    return Ok((input, opts_or_transforms::transform(transform)));
}

fn parse_indicator_set_kv(input: &str) -> IResult<&str, IndicatorOpt> {
    let (input, _) = spaces(input)?;
    let (input, name) = token(input)?;
    let (input, _) = spaces(input)?;
    let (input, (k, _, v)) = tuple((quote_value, tag(" "), quote_value))(input)?; // bad
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
    let result = many0(parse_set_option_local)(input);
    dbg!(result);
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
    assert_eq!(
        result.unwrap().1,
        RoleIndicator {
            role: "client".to_string(),
            set_opts: [
                IndicatorOpt {
                    name: "header".to_string(),
                    k: "Accept".to_string(),
                    v: "*/*".to_string(),
                },
                IndicatorOpt {
                    name: "header".to_string(),
                    k: "Content-Type".to_string(),
                    v: "text/xml".to_string(),
                },
                IndicatorOpt {
                    name: "header".to_string(),
                    k: "X-Requested-With".to_string(),
                    v: "XMLHttpRequest".to_string(),
                },
                IndicatorOpt {
                    name: "header".to_string(),
                    k: "Host".to_string(),
                    v: "www.amazon.com".to_string(),
                },
                IndicatorOpt {
                    name: "parameter".to_string(),
                    k: "sz".to_string(),
                    v: "160x600".to_string(),
                },
                IndicatorOpt {
                    name: "parameter".to_string(),
                    k: "oe".to_string(),
                    v: "oe=ISO-8859-1;".to_string(),
                },
                IndicatorOpt {
                    name: "parameter".to_string(),
                    k: "s".to_string(),
                    v: "3717".to_string(),
                },
                IndicatorOpt {
                    name: "parameter".to_string(),
                    k: "dc_ref".to_string(),
                    v: "http%3A%2F%2Fwww.amazon.com".to_string(),
                },
            ]
            .to_vec(),
            transforms: [
                TransformActions {
                    name: "id".to_string(),
                    actions: [Action::parameter("sn".to_string(),),].to_vec(),
                },
                TransformActions {
                    name: "output".to_string(),
                    actions: [Action::base64, Action::print,].to_vec(),
                },
            ]
            .to_vec(),
        }
    );
}

#[test]
fn test_parse_profile() {
    let input = r#"
    set sleeptime "5000";
    set jitter    "0";
    set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";
    dns-beacon {
        set maxdns "255";
    }

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

    http-post {

        set uri "/N4215/adj/amzn.us.sr.aps";

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

        server {

            header "Server" "Server";
            header "x-amz-id-1" "THK9YEZJCKPGY5T42OZT";
            header "x-amz-id-2" "a21JZ1xrNDNtdGRsa219bGV3YW85amZuZW9zdG5rZmRuZ2tmZGl4aHRvNDVpbgo=";
            header "X-Frame-Options" "SAMEORIGIN";
            header "x-ua-compatible" "IE=edge";

            output {
                print;
            }
        }
    }


    "#;
    let result = parse_profile(input);
    // dbg!(result);
    assert_eq!(result.unwrap().1,
            Profile {
                global_options: [
                    OptionSet {
                        scope: 0,
                        k: "sleeptime".to_string(),
                        v: "5000".to_string(),
                    },
                    OptionSet {
                        scope: 0,
                        k: "jitter".to_string(),
                        v: "0".to_string(),
                    },
                    OptionSet {
                        scope: 0,
                        k: "useragent".to_string(),
                        v: "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko".to_string(),
                    },
                ].to_vec(),
                transactions: [
                    ProtocolTransaction {
                        proto: "dns-beacon".to_string(),
                        local_options: [
                            OptionSet {
                                scope: 0,
                                k: "maxdns".to_string(),
                                v: "255".to_string(),
                            },
                        ].to_vec(),
                        roles: [].to_vec(),
                    },
                    ProtocolTransaction {
                        proto: "http-get".to_string(),
                        local_options: [
                            OptionSet {
                                scope: 0,
                                k: "uri".to_string(),
                                v: "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books".to_string(),
                            },
                        ].to_vec(),
                        roles: [
                            RoleIndicator {
                                role: "client".to_string(),
                                set_opts: [
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "Accept".to_string(),
                                        v: "*/*".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "Host".to_string(),
                                        v: "www.amazon.com".to_string(),
                                    },
                                ].to_vec(),
                                transforms: [
                                    TransformActions {
                                        name: "metadata".to_string(),
                                        actions: [
                                            Action::base64,
                                            Action::prepend(
                                                "session-token=".to_string(),
                                            ),
                                            Action::prepend(
                                                "skin=noskin;".to_string(),
                                            ),
                                            Action::append(
                                                "csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996".to_string(),
                                            ),
                                            Action::header(
                                                "Cookie".to_string(),
                                            ),
                                        ].to_vec(),
                                    },
                                ].to_vec(),
                            },
                            RoleIndicator {
                                role: "server".to_string(),
                                set_opts: [
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "Server".to_string(),
                                        v: "Server".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "x-amz-id-1".to_string(),
                                        v: "THKUYEZKCKPGY5T42PZT".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "x-amz-id-2".to_string(),
                                        v: "a21yZ2xrNDNtdGRsa212bGV3YW85amZuZW9ydG5rZmRuZ2tmZGl4aHRvNDVpbgo=".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "X-Frame-Options".to_string(),
                                        v: "SAMEORIGIN".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "Content-Encoding".to_string(),
                                        v: "gzip".to_string(),
                                    },
                                ].to_vec(),
                                transforms: [
                                    TransformActions {
                                        name: "output".to_string(),
                                        actions: [
                                            Action::print,
                                        ].to_vec(),
                                    },
                                ].to_vec(),
                            },
                        ].to_vec(),
                    },
                    ProtocolTransaction {
                        proto: "http-post".to_string(),
                        local_options: [
                            OptionSet {
                                scope: 0,
                                k: "uri".to_string(),
                                v: "/N4215/adj/amzn.us.sr.aps".to_string(),
                            },
                        ].to_vec(),
                        roles: [
                            RoleIndicator {
                                role: "client".to_string(),
                                set_opts: [
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "Accept".to_string(),
                                        v: "*/*".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "Content-Type".to_string(),
                                        v: "text/xml".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "X-Requested-With".to_string(),
                                        v: "XMLHttpRequest".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "Host".to_string(),
                                        v: "www.amazon.com".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "parameter".to_string(),
                                        k: "sz".to_string(),
                                        v: "160x600".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "parameter".to_string(),
                                        k: "oe".to_string(),
                                        v: "oe=ISO-8859-1;".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "parameter".to_string(),
                                        k: "s".to_string(),
                                        v: "3717".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "parameter".to_string(),
                                        k: "dc_ref".to_string(),
                                        v: "http%3A%2F%2Fwww.amazon.com".to_string(),
                                    },
                                ].to_vec(),
                                transforms: [
                                    TransformActions {
                                        name: "id".to_string(),
                                        actions: [
                                            Action::parameter(
                                                "sn".to_string(),
                                            ),
                                        ].to_vec(),
                                    },
                                    TransformActions {
                                        name: "output".to_string(),
                                        actions: [
                                            Action::base64,
                                            Action::print,
                                        ].to_vec(),
                                    },
                                ].to_vec(),
                            },
                            RoleIndicator {
                                role: "server".to_string(),
                                set_opts: [
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "Server".to_string(),
                                        v: "Server".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "x-amz-id-1".to_string(),
                                        v: "THK9YEZJCKPGY5T42OZT".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "x-amz-id-2".to_string(),
                                        v: "a21JZ1xrNDNtdGRsa219bGV3YW85amZuZW9zdG5rZmRuZ2tmZGl4aHRvNDVpbgo=".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "X-Frame-Options".to_string(),
                                        v: "SAMEORIGIN".to_string(),
                                    },
                                    IndicatorOpt {
                                        name: "header".to_string(),
                                        k: "x-ua-compatible".to_string(),
                                        v: "IE=edge".to_string(),
                                    },
                                ].to_vec(),
                                transforms: [
                                    TransformActions {
                                        name: "output".to_string(),
                                        actions: [
                                            Action::print,
                                        ].to_vec(),
                                    },
                                ].to_vec(),
                            },
                        ].to_vec(),
                    },
                ].to_vec(),
            },
        )
}

#[test]
fn TODO_test11() {
    let res = multispace1::<&str, ()>("\n    1");
    let res = spaces("");
    dbg!(res);
}
