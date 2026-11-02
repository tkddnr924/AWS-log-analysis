//! Parquet input. Each row is rendered as one JSON object, so a Parquet file
//! reads like an NDJSON file and the NDJSON detection, preview and
//! normalizers apply unchanged (docs/03 "Parquet").

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use duckdb::arrow::array::{Array, AsArray, StructArray};
use duckdb::arrow::datatypes::DataType;
use duckdb::{Connection, Statement};

/// First (and last) four bytes of every Parquet file.
const MAGIC: &[u8; 4] = b"PAR1";

/// One in-memory DuckDB for the process, with idle connections to it kept
/// for reuse: opening a database per file would dominate a corpus of 100k+
/// small hourly files. A static, not a thread-local: dropping a DuckDB
/// connection from a thread-local destructor crashed the process.
static POOL: Mutex<Pool> = Mutex::new(Pool {
    database: None,
    idle: Vec::new(),
});

struct Pool {
    database: Option<Connection>,
    idle: Vec<Connection>,
}

/// Whether `path` starts with the Parquet magic. Unreadable reads as `false`;
/// the caller's own open reports the error.
pub(crate) fn is_parquet(path: &Path) -> bool {
    let mut magic = [0u8; 4];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .is_ok_and(|()| &magic == MAGIC)
}

pub(crate) fn has_magic(head: &[u8]) -> bool {
    head == MAGIC
}

/// Exact row count from the footer; no row data is read.
pub(crate) fn row_count(path: &Path) -> Result<u64, String> {
    let file = sql_literal(path)?;
    with_conn(|conn| {
        conn.query_row(
            &format!("SELECT sum(num_rows)::UBIGINT FROM parquet_file_metadata({file})"),
            [],
            |row| row.get(0),
        )
    })
}

/// Streams rows of one file as JSON text through a [`Rows`] cursor.
pub(crate) fn with_rows<T>(
    path: &Path,
    read: impl FnOnce(&mut Rows<'_, '_>) -> T,
) -> Result<T, String> {
    let file = sql_literal(path)?;
    // Hive partitioning off: a `key=value` directory must not add columns
    // the file itself does not hold.
    let sql = format!(
        "SELECT to_json(t)::VARCHAR FROM read_parquet({file}, hive_partitioning = false) t"
    );
    with_conn(|conn| {
        let mut stmt = conn.prepare(&sql)?;
        // `stream_arrow` executes in streaming mode; its iterator panics on
        // a fetch error, so chunks are pulled through `step` instead.
        drop(stmt.stream_arrow([])?);
        Ok(read(&mut Rows {
            stmt: &stmt,
            chunk: None,
            next: 0,
        }))
    })
}

/// Pull cursor over one query's rows, one DuckDB chunk in memory at a time.
pub(crate) struct Rows<'s, 'c> {
    stmt: &'s Statement<'c>,
    chunk: Option<StructArray>,
    next: usize,
}

impl Rows<'_, '_> {
    /// Appends the next row's JSON to `out`. `Ok(false)` at the end.
    pub(crate) fn read_into(&mut self, out: &mut String) -> Result<bool, String> {
        loop {
            if let Some(chunk) = &self.chunk {
                let column = chunk.column(0);
                while self.next < column.len() {
                    let index = self.next;
                    self.next += 1;
                    if let Some(text) = arrow_text(column.as_ref(), index) {
                        out.push_str(text);
                        return Ok(true);
                    }
                }
            }
            match self.stmt.step() {
                Ok(Some(chunk)) => {
                    self.chunk = Some(chunk);
                    self.next = 0;
                }
                Ok(None) => return Ok(false),
                Err(error) => return Err(read_error(error)),
            }
        }
    }
}

/// One string cell of a DuckDB Arrow chunk; `None` for null or a non-string
/// column. Also used by the store's JSONL export.
pub(crate) fn arrow_text(array: &dyn Array, index: usize) -> Option<&str> {
    if array.is_null(index) {
        return None;
    }
    match array.data_type() {
        DataType::Utf8 => Some(array.as_string::<i32>().value(index)),
        DataType::LargeUtf8 => Some(array.as_string::<i64>().value(index)),
        DataType::Utf8View => Some(array.as_string_view().value(index)),
        _ => None,
    }
}

fn with_conn<T>(run: impl FnOnce(&Connection) -> duckdb::Result<T>) -> Result<T, String> {
    let conn = checkout().map_err(read_error)?;
    let result = run(&conn).map_err(read_error);
    POOL.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .idle
        .push(conn);
    result
}

fn checkout() -> duckdb::Result<Connection> {
    let mut pool = POOL.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(conn) = pool.idle.pop() {
        return Ok(conn);
    }
    let database = match &mut pool.database {
        Some(database) => database,
        empty => empty.insert(open()?),
    };
    database.try_clone()
}

fn open() -> duckdb::Result<Connection> {
    let conn = Connection::open_in_memory()?;
    // Files are already read in parallel, one per worker, each query on its
    // caller's thread; DuckDB worker threads would multiply that. Extensions
    // are linked in and must never be downloaded (docs/07).
    conn.execute_batch(
        "SET threads = 1;
         SET enable_progress_bar = false;
         SET autoinstall_known_extensions = false;
         SET autoload_known_extensions = false;",
    )?;
    Ok(conn)
}

fn read_error(error: duckdb::Error) -> String {
    crate::logging::redact(&format!("parquet read failed: {error}"))
}

/// `path` as a quoted SQL string literal.
fn sql_literal(path: &Path) -> Result<String, String> {
    let text = path
        .to_str()
        .ok_or_else(|| "parquet path is not valid UTF-8".to_owned())?;
    Ok(format!("'{}'", text.replace('\'', "''")))
}
