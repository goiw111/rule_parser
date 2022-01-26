use nom::branch::alt;
use nom::bytes::complete::escaped;
use nom::bytes::complete::tag;
use nom::bytes::complete::tag_no_case;
use nom::bytes::complete::take_while_m_n;
use nom::character::complete::char;
use nom::character::complete::space0;
use nom::combinator::map;
use nom::combinator::opt;
use nom::combinator::value;
use nom::multi::fold_many0;
use nom::multi::fold_many_m_n;
use nom::sequence::delimited;
use nom::sequence::pair;
use nom::sequence::preceded;
use nom::sequence::terminated;
use nom::sequence::tuple;
use nom::IResult;
use nom::Parser;

#[derive(Clone, Debug, PartialEq)]
pub enum Norm {
    Header(String, String),
    Method(Vec<Method>),
    Host(String),
    HostHeader(String),
    Path(String),
    PathPrefix(String),
    Query(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
}

fn e_method_parser(i: &str) -> IResult<&str, Method> {
    alt((
        value(Method::Get, tag_no_case("GET")),
        value(Method::Post, tag_no_case("POST")),
        value(Method::Put, tag_no_case("PUT")),
        value(Method::Delete, tag_no_case("DELETE")),
        value(Method::Patch, tag_no_case("PATCH")),
        value(Method::Head, tag_no_case("HEAD")),
    ))(i)
}

fn method_parser(i: &str) -> IResult<&str, Norm> {
    tuple((
        tag("Method"),
        space0,
        char('('),
        fold_many_m_n(
            0,
            6,
            terminated(delimited(space0, e_method_parser, space0), char(',')),
            || Vec::with_capacity(6),
            |mut v: Vec<Method>, i| (v.push(i), v).1,
        ),
        delimited(space0, e_method_parser, space0),
        char(')'),
    ))
    .map(|t| {
        let mut v = t.3;
        v.push(t.4);
        Norm::Method(v)
    })
    .parse(i)
}

fn header_parser(i: &str) -> IResult<&str, Norm> {
    tuple((
        tag("Header"),
        space0,
        char('('),
        preceded(space0, char('\'')),
        escaped(take_while_m_n(0, 255, |c| c != '\''), '\\', char('\'')),
        char('\''),
        preceded(space0, char(',')),
        preceded(space0, char('\'')),
        escaped(take_while_m_n(0, 255, |c| c != '\''), '\\', char('\'')),
        char('\''),
        preceded(space0, char(')')),
    ))
    .map(|t| Norm::Header(String::from(t.4), String::from(t.8)))
    .parse(i)
}

fn the_rest_parser(i: &str) -> IResult<&str, Norm> {
    tuple((
        alt((
            tuple((tag("HostHeader"), space0, char('('))),
            tuple((tag("Host"), space0, char('('))),
            tuple((tag("Path"), space0, char('('))),
            tuple((tag("PathPrefix"), space0, char('('))),
            tuple((tag("Query"), space0, char('('))),
        )),
        preceded(space0, char('\'')),
        escaped(take_while_m_n(0, 2048, |c| c != '\''), '\\', char('\'')),
        char('\''),
        preceded(space0, char(')')),
    ))
    .map(|t| {
        let mut s = String::with_capacity(2048);
        match t.0 .0 {
            "HostHeader" => {
                s.push_str(t.2);
                Norm::HostHeader(s)
            }
            "Host" => {
                s.push_str(t.2);
                Norm::Host(s)
            }
            "Path" => {
                s.push_str(t.2);
                Norm::Path(s)
            }
            "PathPrefix" => {
                s.push_str(t.2);
                Norm::PathPrefix(s)
            }
            "Query" => {
                s.push_str(t.2);
                Norm::Query(s)
            }
            _ => panic!(),
        }
    })
    .parse(i)
}

#[derive(Clone, Debug, PartialEq)]
pub enum Operator {
    And,
    Or,
    Xor,
}

fn operator_parser(i: &str) -> IResult<&str, Operator> {
    alt((
        value(Operator::And, char('&')),
        value(Operator::Or, char('|')),
        value(Operator::Xor, char('^')),
    ))(i)
}

#[derive(Debug, PartialEq, Clone)]
enum RType {
    Matcher(Norm),
    Rule(Box<Rule>, Vec<(Operator, Rule)>),
}

#[derive(Debug, PartialEq, Clone)]
pub struct Rule {
    is_not: bool,
    r_type: RType,
}

impl Rule {
    pub fn new<const NOT: bool>(m: Norm) -> Self {
        Rule {
            is_not: NOT,
            r_type: RType::Matcher(m),
        }
    }
    pub fn push<const NOT: bool>(mut self, o: Operator, m: Norm) -> Self {
        let this = &mut self;
        match this.r_type {
            RType::Matcher(_) => Rule {
                is_not: false,
                r_type: RType::Rule(
                    Box::new(self),
                    vec![(
                        o,
                        Rule {
                            is_not: NOT,
                            r_type: RType::Matcher(m),
                        },
                    )],
                ),
            },
            RType::Rule(_, ref mut v) => {
                v.push((
                    o,
                    Rule {
                        is_not: NOT,
                        r_type: RType::Matcher(m),
                    },
                ));
                self
            }
        }
    }

    pub fn push_fn<F, const NOT: bool>(mut self, o: Operator, f: F) -> Self
    where
        F: FnOnce() -> Rule,
    {
        let this = &mut self;
        let rule = f();
        match this.r_type {
            RType::Matcher(_) => Rule {
                is_not: false,
                r_type: RType::Rule(
                    Box::new(self),
                    vec![(
                        o,
                        Rule {
                            is_not: NOT,
                            r_type: rule.r_type,
                        },
                    )],
                ),
            },
            RType::Rule(_, ref mut v) => {
                v.push((
                    o,
                    Rule {
                        is_not: NOT,
                        r_type: rule.r_type,
                    },
                ));
                self
            }
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct RuleErr;

impl core::str::FromStr for Rule {
    type Err = RuleErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use nom::Finish;
        match rule_parser(s).finish() {
            Ok(("", r)) => Ok(r),
            _ => Err(RuleErr),
        }
    }
}

fn rule_type_parser(i: &str) -> IResult<&str, Rule> {
    pair(
        opt(char('!')),
        alt((
            map(the_rest_parser, |matcher: Norm| RType::Matcher(matcher)),
            map(header_parser, |matcher: Norm| RType::Matcher(matcher)),
            map(method_parser, |matcher: Norm| RType::Matcher(matcher)),
            map(delimited(char('('), rule_parser, char(')')), |r| r.r_type),
        )),
    )
    .map(|t| Rule {
        is_not: t.0.is_some(),
        r_type: t.1,
    })
    .parse(i)
}

fn rule_parser(i: &str) -> IResult<&str, Rule> {
    tuple((
        delimited(space0, rule_type_parser, space0),
        fold_many0(
            pair(operator_parser, delimited(space0, rule_type_parser, space0)),
            || Vec::with_capacity(255),
            |mut v: Vec<_>, i| {
                v.push(i);
                v
            },
        ),
    ))
    .map(|t| {
        if t.1.is_empty() {
            t.0
        } else {
            Rule {
                is_not: false,
                r_type: RType::Rule(Box::new(t.0), t.1),
            }
        }
    })
    .parse(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host() {
        let host = Norm::Host(String::from("google.com"));
        let rule = Rule {
            is_not: false,
            r_type: RType::Matcher(host),
        };
        assert_eq!("Host('google.com')".parse::<Rule>(), Ok(rule.clone()));
        assert_eq!("Host('google.com') hi".parse::<Rule>(), Err(RuleErr));
        assert_eq!(
            "     Host     (    'google.com'     )    ".parse::<Rule>(),
            Ok(rule.clone())
        );
    }

    #[test]
    fn test_header() {
        let header = Norm::Header(String::from("key"), String::from("value"));
        let rule = Rule {
            is_not: false,
            r_type: RType::Matcher(header),
        };
        assert_eq!("Header('key', 'value') hi".parse::<Rule>(), Err(RuleErr));
        assert_eq!(
            "     Header     (    'key'    ,   'value'      )    ".parse::<Rule>(),
            Ok(rule.clone())
        );
        assert_eq!("Header('key', 'value')".parse::<Rule>(), Ok(rule));
    }

    #[test]
    fn test_method() {
        let method = Norm::Method(vec![Method::Get, Method::Post]);
        let rule = Rule {
            is_not: false,
            r_type: RType::Matcher(method),
        };
        assert_eq!("Method(GET, POST)".parse::<Rule>(), Ok(rule.clone()));
        assert_eq!("Method(GET, POST) hi".parse::<Rule>(), Err(RuleErr));
        assert_eq!(
            "     Method     (   GET     ,    POST   )   ".parse::<Rule>(),
            Ok(rule.clone())
        );
    }

    #[test]
    fn test_hostheader() {
        let norm = Norm::HostHeader(String::from("localhost"));
        let rule = Rule {
            is_not: false,
            r_type: RType::Matcher(norm),
        };
        assert_eq!("HostHeader('localhost')".parse::<Rule>(), Ok(rule));
    }

    #[test]
    fn test_path() {
        let norm = Norm::Path(String::from("/to/a/path"));
        let rule = Rule {
            is_not: false,
            r_type: RType::Matcher(norm),
        };
        assert_eq!("Path('/to/a/path')".parse::<Rule>(), Ok(rule));
    }

    #[test]
    fn test_query() {
        let norm = Norm::Query(String::from("key=value"));
        let rule = Rule {
            is_not: false,
            r_type: RType::Matcher(norm),
        };
        assert_eq!("Query('key=value')".parse::<Rule>(), Ok(rule));
    }

    #[test]
    fn test_push() {
        let rule = Rule::new::<false>(Norm::Path(String::from("/hi/to/all")))
            .push::<true>(Operator::And, Norm::Host(String::from("google.com")))
            .push::<false>(Operator::Or, Norm::Query(String::from("key=value")))
            .push::<true>(Operator::Xor, Norm::HostHeader(String::from("loaclhost")));

        assert_eq!(
            "Path('/hi/to/all') & !Host('google.com') | Query('key=value') ^ !HostHeader('loaclhost')"
                .parse::<Rule>(),
            Ok(rule)
        );
    }

    #[test]
    fn test_push_fn() {
        let rule = Rule::new::<false>(Norm::Path(String::from("/hi/to/all")))
            .push::<true>(Operator::Xor, Norm::Host(String::from("localhost")))
            .push_fn::<_, false>(Operator::And, || {
                Rule::new::<true>(Norm::Path(String::from("/hi/to/all/fn")))
                    .push::<false>(Operator::Or, Norm::Host(String::from("localhost.local")))
            });

        assert_eq!(rule_parser("Path('/hi/to/all') ^ !Host('localhost') & ( !Path('/hi/to/all/fn') | Host('localhost.local'))"),
            Ok(("",rule))
        );
    }
}
