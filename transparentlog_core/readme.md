# Transparent log Core library

A Rust implementation of Transparent Logs for Skeptical Clients (https://research.swtch.com/tlog).

Currently doesn't implement tiling.

Backends provided by the core library:
- In-memory
- Raw files

There is also a simple client with in-memory caching.

```rust
fn main() -> anyhow::Result<()> {
  // Create a new log
  let mut ml: InMemoryLog<String>=InMemoryLog::default();
  // Create a new client
  let mut client= InMemoryLogClientBuilder::new(&ml)?.build();
  // Append a record to the log
  let rec1 = ml.append(String::from("entry1"))?;
  // Check the log contains the record
  assert_eq!(true, check_record(&mut client,&ml,&rec1)?);
  // Get back the data
  assert_eq!("entry1",ml.get(rec1.id)?.unwrap().as_str());
  Ok(())
}
```