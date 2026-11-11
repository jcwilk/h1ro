//! Pure rendering helpers for compact (token-friendly) output. No I/O, no env, no network.

use serde_json::Value;

/// Escape control whitespace so one record is always exactly one line / fixed tab columns.
pub fn escape_ws(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\t' => o.push_str("\\t"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            c if c.is_control() => o.push(' '),
            c => o.push(c),
        }
    }
    o
}

/// Truncate to `max` chars (0 = unlimited) with an explicit marker. Returns (text, was_truncated).
pub fn truncate(s: &str, max: usize) -> (String, bool) {
    if max == 0 {
        return (s.to_string(), false);
    }
    let n = s.chars().count();
    if n <= max {
        return (s.to_string(), false);
    }
    let head: String = s.chars().take(max).collect();
    (format!("{head}…[+{} chars]", n - max), true)
}

/// One compact table cell: null -> `null`, bool/number as-is, string escaped,
/// nested value as compact JSON. Truncated at `max` chars with a marker.
pub fn cell(v: &Value, max: usize) -> (String, bool) {
    let raw = match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => escape_ws(s),
        other => escape_ws(&other.to_string()),
    };
    truncate(&raw, max)
}

/// Handle embedded on `relationships.program.data`, when the API included that object.
pub fn program_handle<'a>(rec: &'a Value) -> Option<&'a Value> {
    rec.pointer("/relationships/program/data/attributes/handle")
}

/// Field lookup: `id`/`type` at top level, otherwise `attributes.<name>`,
/// otherwise the included program handle for the column name `program`.
pub fn field<'a>(rec: &'a Value, name: &str) -> Option<&'a Value> {
    if name == "id" || name == "type" {
        return rec.get(name);
    }
    if let Some(a) = rec.get("attributes") {
        if let Some(v) = a.get(name) {
            return Some(v);
        }
    }
    if name == "program" {
        if let Some(h) = program_handle(rec) {
            return Some(h);
        }
    }
    rec.get(name)
}

/// All selectable field names across records, in first-seen order (`id` first).
pub fn available_fields(records: &[&Value]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for r in records {
        if r.get("id").is_some() && !out.iter().any(|x| x == "id") {
            out.push("id".into());
        }
        let m = r.get("attributes").and_then(|a| a.as_object()).or_else(|| r.as_object());
        if let Some(m) = m {
            for k in m.keys() {
                if k != "attributes" && k != "relationships" && k != "links" && !out.iter().any(|x| x == k) {
                    out.push(k.clone());
                }
            }
        }
        if program_handle(r).is_some() && !out.iter().any(|x| x == "program") {
            out.push("program".into());
        }
    }
    out
}

/// Default columns when a command has no fixed set: `id` + up to 6 scalar attributes of the first record.
pub fn auto_columns(records: &[&Value]) -> Vec<String> {
    let mut cols = vec!["id".to_string()];
    if let Some(first) = records.first() {
        let m = first.get("attributes").and_then(|a| a.as_object()).or_else(|| first.as_object());
        if let Some(m) = m {
            for (k, v) in m {
                if cols.len() >= 7 {
                    break;
                }
                if k != "id" && !v.is_object() && !v.is_array() {
                    cols.push(k.clone());
                }
            }
        }
    }
    cols
}

/// Header line + one tab-separated line per record. Returns (text, truncated_cell_count).
pub fn table(records: &[&Value], cols: &[String], max: usize) -> (String, usize) {
    let mut out = cols.join("\t");
    out.push('\n');
    let mut trunc = 0;
    for r in records {
        let cells: Vec<String> = cols
            .iter()
            .map(|c| match field(r, c) {
                Some(v) => {
                    let (t, was) = cell(v, max);
                    if was {
                        trunc += 1;
                    }
                    t
                }
                None => "null".to_string(),
            })
            .collect();
        out.push_str(&cells.join("\t"));
        out.push('\n');
    }
    (out, trunc)
}

fn activity_actor(act: &Value) -> Value {
    act.pointer("/relationships/actor/data/attributes/username")
        .or_else(|| act.pointer("/relationships/actor/data/attributes/name"))
        .cloned()
        .unwrap_or(Value::Null)
}

/// Compact table of the activities already included on a report.
/// `None` when the response has no `relationships.activities` key.
/// Attachment URLs inside activities are not copied into the table.
pub fn activities_table(obj: &Value, max: usize) -> Option<(String, usize, usize)> {
    let rel = obj.get("relationships")?.get("activities")?;
    let rows: Vec<&Value> = match rel.get("data") {
        Some(Value::Array(a)) => a.iter().collect(),
        _ => Vec::new(),
    };
    let mut out = "created_at\ttype\tactor\tmessage\n".to_string();
    let mut trunc = 0;
    for act in &rows {
        let actor = activity_actor(act);
        let cells = [
            field(act, "created_at"),
            field(act, "type"),
            Some(&actor),
            field(act, "message"),
        ];
        let mut line: Vec<String> = Vec::with_capacity(4);
        for c in cells {
            match c {
                Some(v) => {
                    let (t, was) = cell(v, max);
                    if was {
                        trunc += 1;
                    }
                    line.push(t);
                }
                None => line.push("null".into()),
            }
        }
        out.push_str(&line.join("\t"));
        out.push('\n');
    }
    Some((out, trunc, rows.len()))
}

fn relation_rows<'a>(node: &'a Value) -> Vec<&'a Value> {
    match node.get("data") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(o @ Value::Object(_)) => vec![o],
        _ => Vec::new(),
    }
}

/// Attachment metadata already embedded on a report: the report's own
/// attachments, plus any nested on its activities. `None` when there are none.
/// The file host in `expiring_url` is not contacted.
pub fn attachments_table(obj: &Value, max: usize) -> Option<(String, usize, usize)> {
    let rel = obj.get("relationships")?;
    let mut rows: Vec<&Value> = Vec::new();
    if let Some(atts) = rel.get("attachments") {
        rows.extend(relation_rows(atts));
    }
    if let Some(acts) = rel.get("activities") {
        for act in relation_rows(acts) {
            if let Some(nested) = act.get("relationships").and_then(|r| r.get("attachments")) {
                rows.extend(relation_rows(nested));
            }
        }
    }
    if rows.is_empty() {
        return None;
    }
    let cols = ["id", "file_name", "content_type", "file_size", "expiring_url"]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let (text, trunc) = table(&rows, &cols, max);
    Some((text, trunc, rows.len()))
}

/// `key<TAB>value` lines for one object. Returns (text, truncated_count, omitted relationship names).
pub fn kv(obj: &Value, max: usize) -> (String, usize, Vec<String>) {
    let mut out = String::new();
    let mut trunc = 0;
    let mut push = |k: &str, v: &Value, out: &mut String| {
        let (t, was) = cell(v, max);
        if was {
            trunc += 1;
        }
        out.push_str(k);
        out.push('\t');
        out.push_str(&t);
        out.push('\n');
    };
    let mut omitted = Vec::new();
    if let Some(attrs) = obj.get("attributes").and_then(|a| a.as_object()) {
        if let Some(id) = obj.get("id") {
            push("id", id, &mut out);
        }
        if let Some(t) = obj.get("type") {
            push("type", t, &mut out);
        }
        for (k, v) in attrs {
            push(k, v, &mut out);
        }
        if let Some(rel) = obj.get("relationships").and_then(|r| r.as_object()) {
            omitted = rel.keys().cloned().collect();
        }
    } else if let Some(m) = obj.as_object() {
        for (k, v) in m {
            push(k, v, &mut out);
        }
    }
    (out, trunc, omitted)
}

/// Percent-decode (for display of hints only).
pub fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(h) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|x| u8::from_str_radix(x, 16).ok()) {
                out.push(h);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Query pairs of a link, decoded. Display only.
pub fn link_pairs(link: &str) -> Vec<(String, String)> {
    let q = match link.split_once('?') {
        Some((_, q)) => q,
        None => return vec![],
    };
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (pct_decode(k), pct_decode(v)),
            None => (pct_decode(p), String::new()),
        })
        .collect()
}

/// A numeric query parameter of a link (e.g. `page[number]`), tolerant of encoded brackets.
pub fn link_num(link: &str, name: &str) -> Option<u32> {
    link_pairs(link)
        .into_iter()
        .find(|(k, _)| k == name)
        .and_then(|(_, v)| v.parse().ok())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageInfo {
    pub page: u32,
    pub size: Option<u32>,
    pub last: Option<u32>,
    pub next_page: Option<u32>,
    pub next_size: Option<u32>,
}

pub fn page_info(v: &Value, req_page: Option<u32>, req_size: Option<u32>) -> PageInfo {
    let links = v.get("links");
    let l = |k: &str| links.and_then(|x| x.get(k)).and_then(|x| x.as_str());
    let page = l("self")
        .and_then(|s| link_num(s, "page[number]"))
        .or(req_page)
        .unwrap_or(1);
    let size = l("self").and_then(|s| link_num(s, "page[size]")).or(req_size);
    let last = l("last").and_then(|s| link_num(s, "page[number]"));
    let next_page = l("next").map(|s| link_num(s, "page[number]").unwrap_or(page + 1));
    let next_size = l("next").and_then(|s| link_num(s, "page[size]")).or(size);
    PageInfo { page, size, last, next_page, next_size }
}
