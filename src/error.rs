error_chain! {
    foreign_links {
        JsonError(::serde_json::Error);
    }
    errors {
        CJoseError(code: u32, message: String, function: String, file: String, line: u64) {
            description("cjose error")
            display("cjose error. Code: {}, Message: {}, Function: {}, File: {}, Line: {}", code, message, function, file, line)
        }
    }
}
