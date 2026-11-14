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
pub fn parse_params<T: DeserializeOwned>(v: Value) -> Result<T, ToolError> {
    let v = if v.is_null() { Value::Object(Default::default()) } else { v };
    serde_path_to_error::deserialize(v).map_err(|error| {
        let pointer = parameter_pointer(error.path());
        let location = pointer.as_deref().filter(|p| !p.is_empty()).map(|p| format!(" at {p:?}")).unwrap_or_default();
        ToolError::invalid(format!("invalid params{location}: {}", error.inner()))
            .with_remediation("Correct the parameter to match the tool's input schema, then call the tool again.")
            .with_details(serde_json::json!({"parameter_path": pointer}))
    })
}

/// Tool params with a number or a boolean the caller wrote as text (`"limit": "200"`, a model's
/// usual slip) read as what the tool's schema says they are. Only where the schema types a value
/// as an integer, a number or a boolean is its text rewritten: a string parameter keeps its text,
/// even when that text is `"200"`. Nested objects follow `properties`, arrays follow `items`, and
/// nothing the schema doesn't describe is touched (#1825). A nested type is usually a `$ref` into
/// the schema's own `$defs` or `definitions`, which is read through by the reference's own path.
pub fn params_as_schema(schema: &Value, params: Value) -> Value {
    typed_as_schema(schema, schema, &params, MAX_PARAM_DEPTH)
}

/// Params are trees the schema bounds, but a self-referencing schema would not end: past this
/// depth a value is taken as written.
const MAX_PARAM_DEPTH: usize = 64;

fn typed_as_schema(schema: &Value, root: &Value, params: &Value, depth: usize) -> Value {
    if depth == 0 {
        return params.clone();
    }
    if let Some(next) = resolve_ref(schema, root) {
        return typed_as_schema(next, root, params, depth - 1);
    }
    match params {
        Value::String(s) => written_as_schema(schema, s, params),
        Value::Object(map) => {
            let properties = schema.get("properties");
            Value::Object(
                map.iter()
                    .map(|(key, value)| match properties.and_then(|p| p.get(key)) {
                        Some(next) => (key.clone(), typed_as_schema(next, root, value, depth - 1)),
                        None => (key.clone(), value.clone()),
                    })
                    .collect(),
            )
        }
        Value::Array(items) => match schema.get("items") {
            Some(next) => Value::Array(items.iter().map(|item| typed_as_schema(next, root, item, depth - 1)).collect()),
            None => params.clone(),
        },
        _ => params.clone(),
    }
}

/// A `$ref` into the schema itself (`#/$defs/Name`, `#/definitions/Name`), read at the path the
/// reference names, so a schema that keeps both dictionaries has each reference obey its own.
fn resolve_ref<'a>(schema: &'a Value, root: &'a Value) -> Option<&'a Value> {
    let reference = schema.get("$ref")?.as_str()?;
    let pointer = reference.strip_prefix('#')?;
    if !pointer.starts_with('/') {
        return None;
    }
    root.pointer(pointer)
}

/// A string the caller wrote. Where the schema allows text, text stays text: a number field that
/// also allows a string keeps `"200"` as written. Where it doesn't, the schema's own kinds decide,
/// in no particular order: an integer, number or boolean the text spells is read as one.
fn written_as_schema(schema: &Value, text: &str, params: &Value) -> Value {
    let kinds = schema_kinds(schema);
    if kinds.contains(&"string") {
        return params.clone();
    }
    let numeric = kinds.iter().any(|kind| matches!(*kind, "integer" | "number"));
    if numeric
        && text.trim() == text
        && !text.is_empty()
        && let Ok(Value::Number(number)) = serde_json::from_str::<Value>(text)
    {
        return Value::Number(number);
    }
    if kinds.contains(&"boolean") {
        match text {
            "true" => return Value::Bool(true),
            "false" => return Value::Bool(false),
            _ => {}
        }
    }
    params.clone()
}

/// A schema's allowed types, whether written as one word or as a list (`["integer", "null"]`).
fn schema_kinds(schema: &Value) -> Vec<&str> {
    match schema.get("type") {
        Some(Value::String(kind)) => vec![kind.as_str()],
        Some(Value::Array(kinds)) => kinds.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
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

    /// #1825: params follow the schema: a number or a boolean written as text is read as one,
    /// a string stays text even when it reads as a number, and undescribed values are untouched.
    #[test]
    fn a_number_the_schema_types_is_read_as_one_and_text_stays_text() {
        let schema = json!({
            "type": "object",
            "properties": {
                "offset": {"type": "integer"},
                "ratio": {"type": ["number", "null"]},
                "deep": {"type": "boolean"},
                "note": {"type": "string"},
                "pages": {"type": "array", "items": {"type": "integer"}}
            }
        });
        let typed = params_as_schema(&schema, json!({"offset": "592", "ratio": "1.5", "deep": "true", "note": "200", "pages": ["1", 2], "other": "3"}));
        assert_eq!(typed, json!({"offset": 592, "ratio": 1.5, "deep": true, "note": "200", "pages": [1, 2], "other": "3"}));
        // Text that isn't the value the schema wants stays as written, so the error still says
        // what is wrong where.
        let typed = params_as_schema(&schema, json!({"deep": "yes", "note": "1"}));
        assert_eq!(typed, json!({"deep": "yes", "note": "1"}));
        assert!(parse_params::<Question>(params_as_schema(&json!({"type": "object"}), json!({"question": "Where?"}))).is_ok());

        // A nested type is a `$ref` into the schema's own `$defs`.
        let nested = json!({
            "type": "object",
            "properties": {"range": {"$ref": "#/$defs/ByteRange"}},
            "$defs": {"ByteRange": {"type": "object", "properties": {"offset": {"type": "integer"}, "length": {"type": "integer"}}}}
        });
        let typed = params_as_schema(&nested, json!({"range": {"offset": "592", "length": "1024"}}));
        assert_eq!(typed, json!({"range": {"offset": 592, "length": 1024}}));

        // A schema that keeps both dictionaries is read by each reference's own path: the one into
        // `definitions` wants text, the one into `$defs` a number.
        let both = json!({
            "type": "object",
            "properties": {"a": {"$ref": "#/definitions/Value"}, "b": {"$ref": "#/$defs/Value"}},
            "definitions": {"Value": {"type": "string"}},
            "$defs": {"Value": {"type": "integer"}}
        });
        let typed = params_as_schema(&both, json!({"a": "200", "b": "200"}));
        assert_eq!(typed, json!({"a": "200", "b": 200}));

        // A list of types is read as a set: the order never decides, and a value the schema also
        // allows as text keeps its text.
        let either = json!({"type": "object", "properties": {"maybe": {"type": ["null", "integer"]}, "or_text": {"type": ["integer", "string"]}}});
        let typed = params_as_schema(&either, json!({"maybe": "200", "or_text": "200"}));
        assert_eq!(typed, json!({"maybe": 200, "or_text": "200"}));
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
        for input in [json!({"count": -1}), json!({"count": "4"}), json!({"count": u64::MAX})] {
            let error = parse_params::<Defaults>(input).unwrap_err();
            assert_eq!(error.details.as_ref().unwrap()["parameter_path"], "/count");
        }
        let missing = parse_params::<Question>(json!({"probes": []})).unwrap_err();
        assert!(missing.message.contains("missing field `question`"));
        assert_eq!(missing.details.as_ref().unwrap()["parameter_path"], "", "the known location is the parent object, not an invented missing value");
        let extra = parse_params::<Question>(json!({"question": "Where?", "surprise": true})).unwrap_err();
        assert!(extra.message.contains("unknown field `surprise`"));
    }
}
