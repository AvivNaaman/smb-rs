use std::io::Read;

use pest::iterators::Pair;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "idl.pest"]
struct IdlParser;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    use pest::Parser;
    // Initialize the logger
    env_logger::init();
    log::info!("Hello, RPC!");

    // Read test/test.idl:
    let contents = {
        let mut file = std::fs::File::open("msrpc/test/test.idl")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        contents
    };

    let pairs = IdlParser::parse(Rule::interface, &contents)?;
    for pair in pairs {
        log::info!("Parsed IDL: \n{}", format_pair(pair, 1, false));
    }
    Ok(())
}

/// https://github.com/pest-parser/pest/discussions/823
fn format_pair(pair: Pair<Rule>, indent_level: usize, is_newline: bool) -> String {
    let indent = if is_newline {
        "  ".repeat(indent_level)
    } else {
        String::new()
    };

    let children: Vec<_> = pair.clone().into_inner().collect();
    let len = children.len();
    let children: Vec<_> = children
        .into_iter()
        .map(|pair| {
            format_pair(
                pair,
                if len > 1 {
                    indent_level + 1
                } else {
                    indent_level
                },
                len > 1,
            )
        })
        .collect();

    let dash = if is_newline { "- " } else { "" };
    let pair_tag = match pair.as_node_tag() {
        Some(tag) => format!("(#{}) ", tag),
        None => String::new(),
    };
    match len {
        0 => format!(
            "{}{}{}{:?}: {:?}",
            indent,
            dash,
            pair_tag,
            pair.as_rule(),
            pair.as_span().as_str()
        ),
        1 => format!(
            "{}{}{}{:?} > {}",
            indent,
            dash,
            pair_tag,
            pair.as_rule(),
            children[0]
        ),
        _ => format!(
            "{}{}{}{:?}\n{}",
            indent,
            dash,
            pair_tag,
            pair.as_rule(),
            children.join("\n")
        ),
    }
}
