//! # Transparent Log
//!
//! This crate provides an implementation of a Merkle tree for log records, for sceptical clients.
//!
//! See <https://research.swtch.com/tlog>
//!
//! # Examples
//!
//! ```
//! use transparentlog_core::{check_record,InMemoryLog,InMemoryLogClientBuilder,TransparentLog};
//!
//! # fn main() -> anyhow::Result<()> {
//! // Create a new log
//! let mut ml: InMemoryLog<String>=InMemoryLog::default();
//! // Create a new client
//! let mut client= InMemoryLogClientBuilder::new(&ml)?.build();
//! // Append a record to the log
//! let rec1 = ml.append(String::from("entry1"))?;
//! // Check the log contains the record
//! assert_eq!(true, check_record(&mut client,&ml,&rec1)?);
//! // Get back the data
//! assert_eq!("entry1",ml.get(rec1.id)?.unwrap().as_str());
//! # Ok(())
//! # }
//! ```

mod base;
pub use base::*;

mod memory;
pub use memory::*;

mod file;
pub use file::*;

pub mod test_helpers;
