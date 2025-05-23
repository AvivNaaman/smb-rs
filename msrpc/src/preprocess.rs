use std::io::Read;

use pest::{iterators::Pair, Parser};
use pest_derive::Parser;

use crate::util::format_pair;

#[derive(Parser)]
#[grammar = "pp.pest"]
pub struct PreProcessorParser;

pub struct IdlPreProcessor {}

impl IdlPreProcessor {
    pub fn new() -> Self {
        IdlPreProcessor {}
    }

    pub fn process(&self, contents: &str) -> Result<String, Box<dyn std::error::Error>> {
        let pairs = PreProcessorParser::parse(Rule::program, &contents)?;
        for pair in pairs {
            log::info!("Parsed IDL: \n{}", format_pair(pair, 1, false));
        }
        Ok(String::new())
    }
}
