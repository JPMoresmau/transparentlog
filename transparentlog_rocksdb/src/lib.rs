use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use maybe_owned::MaybeOwned;
use rocksdb::{DB, ColumnFamilyDescriptor, Options};
use serde::{Serialize,Deserialize, de::DeserializeOwned};
use transparentlog_core::{TransparentLog, tree_sizes};
use std::{path::Path, marker::PhantomData};

const FAMILY_DATA: &'static str = "data";
const FAMILY_HASH: &'static str = "hash";

// RocksDB implementation of the Transparent log
pub struct RocksDBLog<'a, T:Serialize+Deserialize<'a>> {
    db: DB,
    size: u128,
    _marker: PhantomData<&'a T>
}

impl <'a, T:Serialize+Deserialize<'a>> RocksDBLog<'a, T> {
    // Open a new or existing database
    pub fn open<P: AsRef<Path>>(path: &'a P) -> anyhow::Result<Self> {
        let data_cf = ColumnFamilyDescriptor::new(FAMILY_DATA,  Options::default());
        let hash_cf = ColumnFamilyDescriptor::new(FAMILY_HASH,  Options::default());

        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);

        let db = DB::open_cf_descriptors(&db_opts, path, vec![data_cf,hash_cf]).unwrap();
        let mut size = 0;
        {
            let mut it=db.iterator_cf(db.cf_handle(FAMILY_DATA).unwrap(), rocksdb::IteratorMode::End);
            if let Some((key,_)) = it.next() {
                size =BigEndian::read_u128(key.as_ref()) + 1_u128;
            }
        }
        Ok(Self{
            db, size,
            _marker: PhantomData})
    }
}

// Implement TransparentLog API
impl <'a, T: Serialize+DeserializeOwned> TransparentLog<'a, T> for RocksDBLog<'a,T> {
    type LogSize = u128;

    fn size(&self) -> anyhow::Result<Self::LogSize> {
        Ok(self.size)
    }
 

    fn add(&mut self, record: T) -> anyhow::Result<Self::LogSize> {
        let id=self.size;
        self.db.put_cf(self.db.cf_handle(FAMILY_DATA).unwrap(),id.to_be_bytes(),rmp_serde::to_vec(&record)?)?;
        self.size+=1;
        Ok(id)
    }

    fn add_hash(&mut self,level: transparentlog_core::LogHeight, hash: String) -> anyhow::Result<Self::LogSize> {
        let sizes=tree_sizes(self.size);
        let index=sizes.get(level).unwrap()-1;
        let mut v=vec![];
        v.write_u64::<BigEndian>(level as u64)?;
        v.write_u128::<BigEndian>(index)?;
        self.db.put_cf(self.db.cf_handle(FAMILY_HASH).unwrap(),v,hash)?;
        Ok(index)
    }

    fn get_hash(&self, level: transparentlog_core::LogHeight, index: Self::LogSize) -> anyhow::Result<MaybeOwned<String>> {
        let mut v=vec![];
        v.write_u64::<BigEndian>(level as u64)?;
        v.write_u128::<BigEndian>(index)?;
        let bs = self.db.get_cf(self.db.cf_handle(FAMILY_HASH).unwrap(),v)?.unwrap();
        Ok(String::from_utf8(bs)?.into())
    }


    fn get(&self, index: Self::LogSize) -> anyhow::Result<Option<MaybeOwned<T>>> {
        let obs = self.db.get_cf(self.db.cf_handle(FAMILY_DATA).unwrap(),index.to_be_bytes())?;
        if let Some (bs)=obs {
            let r=rmp_serde::from_read_ref(&bs)?;
            Ok(Some(MaybeOwned::Owned(r)))
        } else {
            Ok(None)
        }
    }

}


#[cfg(test)]
mod tests {

    use transparentlog_core::test_helpers::*;
    use transparentlog_core::InMemoryLogClientBuilder;
    use crate::RocksDBLog;
    use std::path::{Path, PathBuf};
    use std::fs::{create_dir, remove_dir_all};

    use serial_test::serial;
  
    fn setup() ->anyhow::Result<PathBuf>{
        let path=Path::new("./test_data_rocks");
        println!("{} {}",path.display(),path.exists());
        if path.exists(){
            remove_dir_all(&path)?;
        }
        create_dir(&path)?;
        Ok(PathBuf::from(path))
    }


    #[test]
    #[serial]
    fn rocksdb_empty() -> anyhow::Result<()>{
        let path=setup()?;
        let mut ml: RocksDBLog<LogRecord>=RocksDBLog::open(&path)?;
        empty(&mut ml)
    }

    #[test]
    #[serial]
    fn rocksdb_add()-> anyhow::Result<()>{
        let path=setup()?;
        let mut ml: RocksDBLog<LogRecord>=RocksDBLog::open(&path)?;
        add(&mut ml)
    }

    #[test]
    #[serial]
    fn rocksdb_13()-> anyhow::Result<()>{
        let path=setup()?;
        let mut ml: RocksDBLog<LogRecord>=RocksDBLog::open(&path)?;
        test_13(&mut ml)?;
        drop(ml);
        let ml: RocksDBLog<LogRecord>=RocksDBLog::open(&path)?;
        check_13(&ml)
    }

    #[test]
    #[serial]
    fn rocksdb_memory_13()-> anyhow::Result<()>{
        let path=setup()?;
        let mut ml: RocksDBLog<LogRecord>=RocksDBLog::open(&path)?;
        let mut client= InMemoryLogClientBuilder::new(&ml)?.build();
        client_13(&mut ml, &mut client)
    
    }

    #[test]
    #[serial]
    fn rocksdb_memory_13_no_cache()-> anyhow::Result<()>{
        let path=setup()?;
        let mut ml: RocksDBLog<LogRecord>=RocksDBLog::open(&path)?;
        let mut client= InMemoryLogClientBuilder::new(&ml)?.no_cache().build();
        client_13_nocache(&mut ml, &mut client)

    }

    
     #[test]
     #[serial]
     fn rocksdb_verify_tree_prefix()-> anyhow::Result<()>{
        let path=setup()?;
        let mut ml: RocksDBLog<LogRecord>=RocksDBLog::open(&path)?;
        test_verify_tree_prefix(&mut ml)

     }

}