use std::{cell::RefCell, collections::HashMap, io::Read, path};

use pest::{
    iterators::{Pair, Pairs},
    Parser,
};
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
            log::info!("Parsed IDL: {}", format_pair(pair, 1, false));
        }
        Ok(String::new())
    }
}

struct IdlPreProcessorState {
    files: RefCell<HashMap<String, IdlPreProcessedFile>>,
}

impl IdlPreProcessorState {
    fn load_file(&self, file_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(_) = self.files.borrow().get(file_name) {
            return Ok(());
        }

        let mut file = IdlPreProcessedFile::new(file_name);
        file.process(self)?;
        self.files.borrow_mut().insert(file_name.to_string(), file);
        Ok(())
    }
}

enum IdlPreProcessedFileState {
    NotProcessed,
    Processing(HashMap<String, String>),
    Done(String),
}

struct IdlPreProcessedFile {
    file_name: String,
    state: IdlPreProcessedFileState,
}

impl IdlPreProcessedFile {
    pub fn new(file_name: &str) -> Self {
        IdlPreProcessedFile {
            file_name: file_name.to_string(),
            state: IdlPreProcessedFileState::NotProcessed,
        }
    }

    pub fn process(
        &mut self,
        state: &IdlPreProcessorState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if matches!(self.state, IdlPreProcessedFileState::Done(_)) {
            return Ok(());
        }
        if matches!(self.state, IdlPreProcessedFileState::Processing(_)) {
            return Err("File is already being processed".into());
        }

        debug_assert!(matches!(self.state, IdlPreProcessedFileState::NotProcessed));
        self.state = IdlPreProcessedFileState::Processing(HashMap::new());

        let mut contents = String::new();
        let mut file = std::fs::File::open(&self.file_name)?;
        file.read_to_string(&mut contents)?;
        let pair = Self::parse_syntax(&contents)?;

        let mut result = String::new();
        self.process_program(pair, &mut result, state)?;

        self.state = IdlPreProcessedFileState::Done(result);
        Ok(())
    }

    fn parse_syntax<'a>(contents: &'a str) -> Result<Pair<'a, Rule>, Box<dyn std::error::Error>> {
        let pairs = PreProcessorParser::parse(Rule::program, contents)?;
        if pairs.len() != 1 {
            return Err("Invalid syntax".into());
        }
        let pairs = pairs.into_iter().next().unwrap();
        Ok(pairs)
    }

    fn process_program(
        &mut self,
        pair: Pair<Rule>,
        result: &mut String,
        state: &IdlPreProcessorState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for exp_line in pair.into_inner() {
            match exp_line.as_rule() {
                Rule::line => {
                    self.process_line(exp_line, result, state)?;
                }
                Rule::EOI => {}
                _ => {}
            }
        }
        Ok(())
    }

    fn get_result(&self) -> Result<String, Box<dyn std::error::Error>> {
        if let IdlPreProcessedFileState::Done(s) = &self.state {
            return Ok(s.clone());
        }
        Err("File not processed".into())
    }

    fn process_line(
        &mut self,
        line: Pair<Rule>,
        result: &mut String,
        state: &IdlPreProcessorState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug_assert!(matches!(line.as_rule(), Rule::line));
        let line_src = line.get_input().to_string();
        let line_child = line.into_inner();
        if line_child.len() != 1 {
            return Err("Invalid line".into());
        }

        let line_child = line_child.into_iter().next().unwrap();
        match line_child.as_rule() {
            Rule::control_line => self.process_control_line(line_child, result, state)?,
            Rule::conditional => self.process_conditional(line_child, result, state)?,
            Rule::token_string => result.push_str(&line_src),
            _ => unreachable!("Grammar error: expected control line or conditional"),
        }

        result.push('\n');
        Ok(())
    }

    fn process_control_line(
        &mut self,
        control_line: Pair<Rule>,
        result: &mut String,
        state: &IdlPreProcessorState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug_assert!(matches!(control_line.as_rule(), Rule::control_line));
        let control_line_child = control_line.into_inner();
        if control_line_child.len() != 1 {
            return Err("Invalid control line".into());
        }
        let control_line_child = control_line_child.into_iter().next().unwrap();

        match control_line_child.as_rule() {
            Rule::define_line => self.process_define_line(control_line_child, result, state)?,
            Rule::include_line => self.process_include_line(control_line_child, result, state)?,
            _ => unreachable!("Grammar error: expected define line or include line"),
        }

        Ok(())
    }

    fn process_define_line(
        &mut self,
        define_line: Pair<Rule>,
        result: &mut String,
        state: &IdlPreProcessorState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug_assert!(matches!(define_line.as_rule(), Rule::define_line));
        // #define IDENTIFIER TOKEN_STRING
        let mut define_line_inner = define_line.into_inner();
        if define_line_inner.len() != 2 {
            return Err("Invalid define line".into());
        }
        let identifier = define_line_inner.next().unwrap();
        debug_assert!(matches!(identifier.as_rule(), Rule::identifier));
        let token_string = define_line_inner.next().unwrap();
        debug_assert!(matches!(token_string.as_rule(), Rule::token_string));
        let identifier_src = identifier.as_span().as_str();
        let token_string_src = token_string.as_span().as_str();

        if let IdlPreProcessedFileState::Processing(ref mut defines) = self.state {
            defines.insert(identifier_src.to_string(), token_string_src.to_string());
        } else {
            return Err("File not being processed".into());
        }

        Ok(())
    }

    fn process_include_line(
        &mut self,
        include_line: Pair<Rule>,
        result: &mut String,
        state: &IdlPreProcessorState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug_assert!(matches!(include_line.as_rule(), Rule::include_line));
        let path_spec = include_line.into_inner();
        if path_spec.len() != 1 {
            return Err("Invalid include line".into());
        }
        let path_spec = path_spec.into_iter().next().unwrap();
        debug_assert!(matches!(path_spec.as_rule(), Rule::path_spec));
        let path_spec_src = path_spec.as_span().as_str();

        state.load_file(path_spec_src)?;
        let included_file = state
            .files
            .borrow()
            .get(path_spec_src)
            .unwrap()
            .get_result()?;

        let pairs = Self::parse_syntax(&included_file)?;
        self.process_program(pairs, result, state)?;
        Ok(())
    }

    fn process_conditional(
        &mut self,
        conditional: Pair<Rule>,
        result: &mut String,
        state: &IdlPreProcessorState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug_assert!(matches!(conditional.as_rule(), Rule::conditional));
        // #if CONDITION
        // <text>
        // #elif CONDITION?
        // <text>
        // #else?
        // <text>
        // #endif
        for (i, next_condition_part) in conditional.into_inner().enumerate() {
            debug_assert!(matches!(
                next_condition_part.as_rule(),
                Rule::elif_line | Rule::else_part | Rule::endif_line
            ));

            match next_condition_part.as_rule() {
                Rule::if_line => {
                    // Process if line
                    let if_line_inner = next_condition_part.into_inner().next().unwrap();
                    match if_line_inner.as_rule() {
                        Rule::if_line_const => {}
                        Rule::ifdef_line => {
                            // #ifdef IDENTIFIER
                        }
                        Rule::ifndef_line => {}
                        _ => unreachable!(),
                    }
                    // Here you would evaluate the condition
                }
                Rule::elif_line => {}
                Rule::else_part => {
                    // Process else part
                }
                Rule::endif_line => {
                    // End of conditional
                    break;
                }
                _ => unreachable!(),
            }
        }

        Ok(())
    }
}
