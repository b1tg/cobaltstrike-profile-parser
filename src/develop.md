# TODO

- 处理注释，现在的测试用例里面去掉了注释
- 整理可复用代码为一个单独的 parser

# 草稿

基于 amazon.profile


// set sleeptime "5000";
parse_set_option_global

//     set maxdns "255";
parse_set_option_local

// http-get {

// }
parse_protocol_transaction
    many0(alt((parse_set_option_local, parse_role?_indicators)))

    // client {

    //     header "Accept" "*/*";
    //     header "Host" "www.amazon.com";

    //     metadata {
    //         base64;
    //         prepend "session-token=";
    //         prepend "skin=noskin;";
    //         append "csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996";
    //         header "Cookie";
    //     }
    // }

parse_role?_indicators
    many0(alt((parse_indicator_set_kv, parse_transform_actions)))


    // parameter "sz" "160x600";
parse_indicator_set_kv



    // output {
    //     base64;
    //     print;
    // }
parse_transform_actions
    many0(alt((parse_transform_action)))


        // base64;
parse_transform_action
