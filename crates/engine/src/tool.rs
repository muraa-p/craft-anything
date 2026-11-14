//! Tool specs: the single contract the UI, CLI, MCP server and built-in agent all dispatch through.

use crate::session::Session;
use bitflags::bitflags;
use craft_anything_evidence::{Evidence, ToolError};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

bitflags! {
    /// Side effects of a tool. Every tool declares them; MCP hints and consent are derived from them.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Effects: u16 {
        /// Records evidence or changes session state (almost every analysis tool).
        const MUTATES_SESSION = 1 << 0;
        /// Changes the target or its annotations (rename, comment).
        const MUTATES_TARGET = 1 << 1;
        const WRITES_FILESYSTEM = 1 << 2;
        const LAUNCHES_PROCESS = 1 << 3;
        const ACCESSES_NETWORK = 1 << 4;
        const CHANGES_UI_STATE = 1 << 5;
        const MAY_DISCARD_DATA = 1 << 6;
        /// Runs code from the target or a script (process capture, Frida, walkthroughs). Needs consent.
        const EXECUTES_FOREIGN_CODE = 1 << 7;
        /// Changes a connected device (install, push, start). Needs consent.
        const MUTATES_DEVICE = 1 << 8;
        const IDEMPOTENT = 1 << 9;
        /// Its result carries content taken from the target (decompiled text, strings, bytes,
        /// rows, plist values): clients are told to treat it as untrusted data.
        const CARRIES_TARGET_CONTENT = 1 << 10;
    }
}

impl Effects {
    /// Plain evidence-producing analysis.
    pub const EVIDENCE: Effects = Effects::MUTATES_SESSION.union(Effects::IDEMPOTENT);
    /// Evidence that needs an engine process.
    pub const NATIVE_EVIDENCE: Effects = Effects::EVIDENCE.union(Effects::LAUNCHES_PROCESS);
    /// Evidence that talks to a browser or device over the network.
    pub const NETWORK_EVIDENCE: Effects = Effects::EVIDENCE.union(Effects::ACCESSES_NETWORK);
    /// Pure reads with no effect at all.
    pub const READ_ONLY: Effects = Effects::IDEMPOTENT;

    pub fn read_only_hint(self) -> bool {
        (self - Effects::IDEMPOTENT).is_empty()
    }

    pub fn destructive_hint(self) -> bool {
        self.intersects(Effects::MAY_DISCARD_DATA | Effects::EXECUTES_FOREIGN_CODE | Effects::MUTATES_DEVICE)
    }

    pub fn open_world_hint(self) -> bool {
        self.intersects(Effects::LAUNCHES_PROCESS | Effects::ACCESSES_NETWORK)
    }

    pub fn needs_consent(self) -> bool {
        self.intersects(Effects::EXECUTES_FOREIGN_CODE | Effects::MUTATES_DEVICE)
    }
}

/// Groups of tools. Agents see `Core` plus whatever toolsets they enable, which keeps their
/// context small. Every tool is always reachable from the CLI and UI. The built-in groups are
/// listed here; a plugin or a fork adds its own with [`Toolset::Custom`] (see
/// [`crate::registry::RuntimeTool`]), and [`crate::Registry::toolsets`] lists every group in use.
/// Serialized as its id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Toolset {
    /// Triage, open/close, overview, search, decompile, function dossier, views, evidence, unknowns.
    Core,
    /// Deep native: listings, navigation, annotations, xrefs, bytes, call graphs, value traces.
    Native,
    /// Mach-O, code signing, plists, Swift/ObjC, Interface Builder, asset catalogs, dyld.
    Apple,
    /// Target-free formats and diagnostics: Go, WASM, EVM, PE resources, ELF layout, crashes, firmware.
    Formats,
    /// .NET assemblies.
    Managed,
    /// APK, DEX, resources, Flutter, JEB.
    Android,
    /// Java `.class` files and JAR/WAR archives: constant pool, bytecode, pseudo-Java.
    Java,
    /// A phone or emulator over adb.
    Adb,
    /// Web pages through the browser debugging protocol.
    Browser,
    /// Electron apps, JavaScript bundles and the V8 inspector.
    Javascript,
    /// Running programs: process capture, native calls, native UI.
    Runtime,
    /// Frida instrumentation.
    Frida,
    /// Application graphs, comparisons and rebuild (reconstruction) ledgers.
    Application,
    /// Databases on disk: SQLite file inspection.
    Database,
    /// What the person is making: projects, their conversation and questions.
    Projects,
    /// Setting up this computer: engines and settings.
    Setup,
    /// A builder's own hands: reading, writing and building the project it works in.
    Build,
    /// A group added at run time (its id, lower-case letters, digits and `_`).
    Custom(&'static str),
}

impl Serialize for Toolset {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.id())
    }
}

impl Toolset {
    pub const ALL: [Toolset; 17] = [
        Toolset::Core,
        Toolset::Native,
        Toolset::Apple,
        Toolset::Formats,
        Toolset::Managed,
        Toolset::Android,
        Toolset::Java,
        Toolset::Adb,
        Toolset::Browser,
        Toolset::Javascript,
        Toolset::Runtime,
        Toolset::Frida,
        Toolset::Application,
        Toolset::Database,
        Toolset::Projects,
        Toolset::Setup,
        Toolset::Build,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Toolset::Core => "core",
            Toolset::Native => "native",
            Toolset::Apple => "apple",
            Toolset::Formats => "formats",
            Toolset::Managed => "managed",
            Toolset::Android => "android",
            Toolset::Java => "java",
            Toolset::Adb => "adb",
            Toolset::Browser => "browser",
            Toolset::Javascript => "javascript",
            Toolset::Runtime => "runtime",
            Toolset::Frida => "frida",
            Toolset::Application => "application",
            Toolset::Database => "database",
            Toolset::Projects => "projects",
            Toolset::Setup => "setup",
            Toolset::Build => "build",
            Toolset::Custom(id) => id,
        }
    }

    /// A built-in group by id. Groups added at run time are found with [`crate::Registry::toolset`].
    pub fn from_id(s: &str) -> Option<Toolset> {
        Toolset::ALL.into_iter().find(|t| t.id() == s)
    }

    pub fn title(self) -> &'static str {
        match self {
            Toolset::Core => "Essentials",
            Toolset::Native => "Programs (native code)",
            Toolset::Apple => "Apple apps",
            Toolset::Formats => "File formats",
            Toolset::Managed => ".NET apps",
            Toolset::Android => "Android apps",
            Toolset::Java => "Java programs",
            Toolset::Adb => "Connected phone",
            Toolset::Browser => "Websites",
            Toolset::Javascript => "Electron and JavaScript",
            Toolset::Runtime => "Running programs",
            Toolset::Frida => "Frida instrumentation",
            Toolset::Application => "Comparing and rebuilding",
            Toolset::Database => "Databases",
            Toolset::Projects => "Projects",
            Toolset::Setup => "Engines and settings",
            Toolset::Build => "Building",
            Toolset::Custom(id) => id,
        }
    }
}

/// What a tool needs before it can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Requires {
    #[default]
    Nothing,
    /// An open target.
    Target,
    /// The Deep (Ghidra) engine to be enabled and installed.
    Ghidra,
    /// An external tool, by engine id (`adb`, `jadx`, `chromium`, `frida`, …).
    Engine(&'static str),
    /// One of these hosts, by `std::env::consts::OS` name (`macos`, `windows`, `linux`).
    Os(&'static [&'static str]),
}

/// Who invoked a tool. Programmatic callers never get dialogs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Caller {
    Ui,
    Cli,
    Mcp,
    Agent,
}

/// Set in the environment of every coding agent Craft Anything starts, and inherited by what it
/// runs, so a `craft-anything-cli` a builder starts calls tools as [`Caller::Agent`], not as the
/// person (it can't loosen a project's approvals that way).
pub const AGENT_ENV: &str = "CRAFT_ANYTHING_AGENT";

/// Cooperative cancellation, shared with long-running work (it lives in `platform`, so the
/// transports below the engine can take it too).
pub use craft_anything_platform::cancel::CancelToken;

/// Progress reports from a running tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Progress {
    /// 0..=1 when known.
    pub fraction: Option<f32>,
    pub message: String,
}

pub type ProgressFn = dyn Fn(Progress) + Send + Sync;

/// Everything a tool run can touch.
pub struct Ctx<'a> {
    /// The id of the tool being run (one function can serve several tools added at run time).
    pub tool: &'static str,
    pub session: &'a mut Session,
    pub cancel: CancelToken,
    pub progress: &'a ProgressFn,
    pub caller: Caller,
}

impl Ctx<'_> {
    pub fn report(&self, fraction: Option<f32>, message: impl Into<String>) {
        (self.progress)(Progress { fraction, message: message.into() });
    }
}

/// What a tool returns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ToolOutput {
    /// An evidence record; the engine stores it in the session ledger.
    Evidence(Box<Evidence>),
    /// A lifecycle or status result that is not itself evidence.
    Value(Value),
}

impl ToolOutput {
    pub fn evidence(e: Evidence) -> Self {
        ToolOutput::Evidence(Box::new(e))
    }

    /// The JSON payload agents see.
    pub fn to_json(&self) -> Value {
        match self {
            ToolOutput::Evidence(e) => serde_json::to_value(e).unwrap_or(Value::Null),
            ToolOutput::Value(v) => serde_json::json!({ "result": v }),
        }
    }
}

pub type ToolFn = fn(&mut Ctx<'_>, Value) -> Result<ToolOutput, ToolError>;

/// A registered tool.
#[derive(Clone, Copy)]
pub struct ToolSpec {
    /// snake_case id; also the MCP tool name. The CLI uses the kebab-case form.
    pub id: &'static str,
    pub title: &'static str,
    /// One or two sentences for agents and experienced users.
    pub summary: &'static str,
    /// Plain-English description for Beginner mode.
    pub beginner: &'static str,
    pub toolset: Toolset,
    pub effects: Effects,
    pub requires: Requires,
    pub input_schema: fn() -> Value,
    pub run: ToolFn,
}

impl std::fmt::Debug for ToolSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolSpec").field("id", &self.id).field("toolset", &self.toolset).finish()
    }
}

impl ToolSpec {
    pub fn cli_name(&self) -> String {
        self.id.replace('_', "-")
    }
}

/// JSON Schema for a params type.
pub fn schema_of<T: schemars::JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).unwrap_or(Value::Null)
}

/// The schema of a tool that takes no params.
pub fn empty_schema() -> Value {
    serde_json::json!({"type": "object", "properties": {}, "additionalProperties": false})
}

/// Parse tool params; `null` is treated as `{}` so programmatic callers can omit them.
///
/// Some callers (notably AI models) send numbers as JSON strings. Those are coerced to the
/// expected numeric type instead of being rejected, so a mistyped `"200"` does not fail the
/// call (and trigger an endless retry loop, #1825).
pub fn parse_params<T: DeserializeOwned>(v: Value) -> Result<T, ToolError> {
    let mut v = if v.is_null() { Value::Object(Default::default()) } else { v };
    loop {
        match serde_path_to_error::deserialize::<_, T>(&v) {
            Ok(parsed) => return Ok(parsed),
            Err(error) => {
                let pointer = parameter_pointer(error.path());
                let message = error.inner().to_string();
                if coerce_numeric_string(&mut v, pointer.as_deref(), &message) {
                    continue;
                }
                let location = pointer.as_deref().filter(|p| !p.is_empty()).map(|p| format!(" at {p:?}")).unwrap_or_default();
                return Err(ToolError::invalid(format!("invalid params{location}: {message}"))
                    .with_remediation("Correct the parameter to match the tool's input schema, then call the tool again.")
                    .with_details(serde_json::json!({"parameter_path": pointer})));
            }
        }
    }
}

/// The numeric type a rejected parameter was expected to be, taken from Serde's error text.
#[derive(Clone, Copy)]
enum ExpectedNumber {
    U8,
    U16,
    U32,
    U64,
    Usize,
    I8,
    I16,
    I32,
    I64,
    Isize,
    F32,
    F64,
    Number,
}

fn expected_number(message: &str) -> Option<ExpectedNumber> {
    let m = message.to_ascii_lowercase();
    if !m.contains("expected") {
        return None;
    }
    if m.contains("usize") {
        Some(ExpectedNumber::Usize)
    } else if m.contains("isize") {
        Some(ExpectedNumber::Isize)
    } else if m.contains("u64") {
        Some(ExpectedNumber::U64)
    } else if m.contains("u32") {
        Some(ExpectedNumber::U32)
    } else if m.contains("u16") {
        Some(ExpectedNumber::U16)
    } else if m.contains("u8") {
        Some(ExpectedNumber::U8)
    } else if m.contains("i64") {
        Some(ExpectedNumber::I64)
    } else if m.contains("i32") {
        Some(ExpectedNumber::I32)
    } else if m.contains("i16") {
        Some(ExpectedNumber::I16)
    } else if m.contains("i8") {
        Some(ExpectedNumber::I8)
    } else if m.contains("f64") {
        Some(ExpectedNumber::F64)
    } else if m.contains("f32") {
        Some(ExpectedNumber::F32)
    } else if m.contains("number") {
        Some(ExpectedNumber::Number)
    } else {
        None
    }
}

/// If `message` says a number was expected and the value at `pointer` is a numeric string,
/// replace it with the number and return `true`.
fn parse_expected_number(text: &str, kind: ExpectedNumber) -> Option<serde_json::Number> {
    match kind {
        ExpectedNumber::U8 => text.parse::<u8>().ok().map(|n| serde_json::Number::from(n as u64)),
        ExpectedNumber::U16 => text.parse::<u16>().ok().map(|n| serde_json::Number::from(n as u64)),
        ExpectedNumber::U32 => text.parse::<u32>().ok().map(|n| serde_json::Number::from(n as u64)),
        ExpectedNumber::U64 => text.parse::<u64>().ok().map(serde_json::Number::from),
        ExpectedNumber::Usize => text.parse::<usize>().ok().map(|n| serde_json::Number::from(n as u64)),
        ExpectedNumber::I8 => text.parse::<i8>().ok().map(|n| serde_json::Number::from(n as i64)),
        ExpectedNumber::I16 => text.parse::<i16>().ok().map(|n| serde_json::Number::from(n as i64)),
        ExpectedNumber::I32 => text.parse::<i32>().ok().map(|n| serde_json::Number::from(n as i64)),
        ExpectedNumber::I64 => text.parse::<i64>().ok().map(serde_json::Number::from),
        ExpectedNumber::Isize => text.parse::<isize>().ok().map(|n| serde_json::Number::from(n as i64)),
        ExpectedNumber::F32 => text.parse::<f32>().ok().and_then(|n| serde_json::Number::from_f64(n as f64)),
        ExpectedNumber::F64 => text.parse::<f64>().ok().and_then(serde_json::Number::from_f64),
        ExpectedNumber::Number => {
            if let Ok(n) = text.parse::<u64>() {
                Some(serde_json::Number::from(n))
            } else if let Ok(n) = text.parse::<i64>() {
                Some(serde_json::Number::from(n))
            } else {
                text.parse::<f64>().ok().and_then(serde_json::Number::from_f64)
            }
        }
    }
}

fn convert_sibling_numeric_strings(value: &mut Value, pointer: &str, kind: ExpectedNumber) {
    // Split the pointer into its parent and the final segment.
    let (parent_ptr, last) = match pointer.rfind('/') {
        Some(0) => ("", &pointer[1..]),
        Some(i) => (&pointer[..i], &pointer[i + 1..]),
        None => return,
    };
    if last.is_empty() {
        return;
    }
    let parent = if parent_ptr.is_empty() {
        value
    } else {
        match value.pointer_mut(parent_ptr) {
            Some(p) => p,
            None => return,
        }
    };
    let Value::Array(items) = parent else {
        return;
    };
    if last.parse::<usize>().is_ok() {
        // The rejected value was one array element; convert every string element.
        for item in items.iter_mut() {
            if let Some(text) = item.as_str()
                && let Some(number) = parse_expected_number(text.trim(), kind)
            {
                *item = Value::Number(number);
            }
        }
    } else {
        // The rejected value was a field inside each array element.
        let field = last;
        for item in items.iter_mut() {
            if let Some(obj) = item.as_object_mut()
                && let Some(v) = obj.get_mut(field)
                && let Some(text) = v.as_str()
                && let Some(number) = parse_expected_number(text.trim(), kind)
            {
                *v = Value::Number(number);
            }
        }
    }
}

fn coerce_numeric_string(value: &mut Value, pointer: Option<&str>, message: &str) -> bool {
    let Some(pointer) = pointer.filter(|p| !p.is_empty()) else {
        return false;
    };
    let Some(kind) = expected_number(message) else {
        return false;
    };
    let Some(target) = value.pointer_mut(pointer) else {
        return false;
    };
    let Some(text) = target.as_str() else {
        return false;
    };
    let text = text.trim();
    let number = parse_expected_number(text, kind);
    let Some(number) = number else {
        return false;
    };
    *target = Value::Number(number);
    convert_sibling_numeric_strings(value, pointer, kind);
    true
}

/// A JSON Pointer to the rejected value, without guessing when Serde cannot locate it.
fn parameter_pointer(path: &serde_path_to_error::Path) -> Option<String> {
    const LIMIT: usize = 1024;
    let mut pointer = String::new();
    for segment in path {
        pointer.push('/');
        match segment {
            serde_path_to_error::Segment::Map { key } if key.len() <= LIMIT => {
                pointer.push_str(&key.replace('~', "~0").replace('/', "~1"));
            }
            serde_path_to_error::Segment::Seq { index } => pointer.push_str(&index.to_string()),
            // Enum variants need not be object keys (for example, internally tagged enums).
            _ => return None,
        }
        if pointer.len() > LIMIT {
            return None;
        }
    }
    Some(pointer)
}

#[cfg(test)]
mod parameter_tests {
    use super::*;
    use craft_anything_evidence::ErrorCode;
    use serde_json::json;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Question {
        question: String,
        #[serde(default)]
        probes: Vec<String>,
    }

    #[test]
    fn an_array_for_a_string_identifies_the_parameter_to_correct() {
        for input in [json!({"question": ["Where?"]}), json!({"question": ["Where?", "Why?"]})] {
            let error = parse_params::<Question>(input).unwrap_err();
            assert_eq!(error.code, ErrorCode::BadInput);
            assert!(error.message.contains("question") && error.message.contains("expected a string"), "{error:?}");
            assert_eq!(error.details.as_ref().unwrap()["parameter_path"], "/question");
            assert!(error.remediation.as_deref().unwrap().contains("call the tool again"));
            assert!(!error.message.contains("Where?"), "the parameter value is not needed to locate the error");
        }
        let valid = parse_params::<Question>(json!({"question": "Where?", "probes": ["inspect"]})).unwrap();
        assert_eq!(valid, Question { question: "Where?".into(), probes: vec!["inspect".into()] });
    }

    #[test]
    fn a_nested_parameter_error_keeps_the_array_index() {
        let error = parse_params::<Question>(json!({"question": "Where?", "probes": ["inspect", ["trace"]]})).unwrap_err();
        assert_eq!(error.details.as_ref().unwrap()["parameter_path"], "/probes/1");
        assert!(error.message.contains("expected a string"), "{error:?}");
    }

    #[test]
    fn a_parameter_path_escapes_json_pointer_keys() {
        #[derive(Debug, Deserialize)]
        struct Envelope {
            #[serde(rename = "a~/b")]
            _questions: Vec<Question>,
        }
        let error = parse_params::<Envelope>(json!({"a~/b": [{"question": ["Where?"]}]})).unwrap_err();
        assert_eq!(error.details.as_ref().unwrap()["parameter_path"], "/a~0~1b/0/question");
    }

    #[test]
    fn oversized_parameter_paths_are_not_reported_as_complete_pointers() {
        let input = json!({"x".repeat(2048): {"question": ["Where?"]}});
        let error = parse_params::<std::collections::BTreeMap<String, Question>>(input).unwrap_err();
        assert!(error.details.as_ref().unwrap()["parameter_path"].is_null());
        assert!(error.message.len() < 200);
        assert!(error.message.contains("expected a string"));
    }

    #[test]
    fn an_enum_path_does_not_guess_a_json_object_location() {
        #[derive(Debug, Deserialize)]
        enum Choice {
            Question(Question),
        }
        let error = parse_params::<Choice>(json!({"Question": {"question": ["Where?"]}})).unwrap_err();
        assert!(error.details.as_ref().unwrap()["parameter_path"].is_null());
        assert!(error.message.contains("expected a string"));
        let Choice::Question(valid) = parse_params::<Choice>(json!({"Question": {"question": "Where?"}})).unwrap();
        assert_eq!(valid.question, "Where?");
    }

    #[test]
    fn parameter_defaults_and_strictness_are_preserved() {
        #[derive(Debug, Default, Deserialize, PartialEq)]
        struct Defaults {
            #[serde(default)]
            count: u32,
        }
        assert_eq!(parse_params::<Defaults>(Value::Null).unwrap(), Defaults::default());
        assert_eq!(parse_params::<Defaults>(json!({"count": 4})).unwrap().count, 4);
        assert_eq!(parse_params::<Defaults>(json!({"count": "4"})).unwrap().count, 4);
        for input in [json!({"count": -1}), json!({"count": u64::MAX})] {
            let error = parse_params::<Defaults>(input).unwrap_err();
            assert_eq!(error.details.as_ref().unwrap()["parameter_path"], "/count");
        }
        let missing = parse_params::<Question>(json!({"probes": []})).unwrap_err();
        assert!(missing.message.contains("missing field `question`"));
        assert_eq!(missing.details.as_ref().unwrap()["parameter_path"], "", "the known location is the parent object, not an invented missing value");
        let extra = parse_params::<Question>(json!({"question": "Where?", "surprise": true})).unwrap_err();
        assert!(extra.message.contains("unknown field `surprise`"));
    }

    #[test]
    fn numeric_strings_are_coerced_to_their_expected_type() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct Numbers {
            limit: usize,
            depth: u8,
            timeout_secs: u64,
            ratio: f64,
        }
        let parsed = parse_params::<Numbers>(json!({
            "limit": "200",
            "depth": "8",
            "timeout_secs": "180",
            "ratio": "1.5"
        }))
        .unwrap();
        assert_eq!(parsed.limit, 200);
        assert_eq!(parsed.depth, 8);
        assert_eq!(parsed.timeout_secs, 180);
        assert_eq!(parsed.ratio, 1.5);
    }

    #[test]
    fn a_number_written_as_text_keeps_its_exact_integer_value() {
        #[derive(Debug, Deserialize)]
        struct Holder {
            n: serde_json::Number,
        }
        let parsed = parse_params::<Holder>(json!({"n": "18446744073709551615"})).unwrap();
        assert_eq!(parsed.n.as_u64(), Some(18_446_744_073_709_551_615));
    }
}
