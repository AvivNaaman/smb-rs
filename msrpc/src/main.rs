use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "idl.pest"]
struct IdlParser;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    use pest::Parser;
    // Initialize the logger
    env_logger::init();
    log::info!("Hello, RPC!");

    IdlParser::parse(Rule::a, "a")
        .map(|pairs| {
            for pair in pairs {
                println!("Rule: {:?}", pair.as_rule());
                println!("Span: {:?}", pair.as_span());
                println!("Text: {}", pair.as_str());
            }
        })?;

    Ok(())
}
