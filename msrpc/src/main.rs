use std::io::Read;

use msrpc::preprocess::IdlPreProcessor;
use pest::iterators::Pair;
use pest_derive::Parser;
// #[derive(Parser)]
// #[grammar = "idl.pest"]
// struct IdlParser;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    use pest::Parser;
    // Initialize the logger
    env_logger::init();
    log::info!("Hello, RPC!");

    // Read test/test.idl:
    let contents = {
        let mut file = std::fs::File::open("msrpc/test/dcerpc.idl")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        contents
    };

    IdlPreProcessor::new().process(&contents)?;
    Ok(())
}
