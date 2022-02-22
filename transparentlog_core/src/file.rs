use std::marker::PhantomData;

use maybe_owned::MaybeOwned;
use std::fmt::Debug;
use std::path::Path;
use std::fs::{File, OpenOptions};
use std::io::{SeekFrom};
use std::io::prelude::*;
use std::cell::RefCell;
pub use crate::base::*;
use serde::{Serialize,Deserialize};
use serde::de::DeserializeOwned;

const HASH_SIZE_IN_BYTES:usize=64;

// An in-memory transparent log
#[derive(Debug)]
pub struct FileLog<'a, T:Serialize+Deserialize<'a>> {
    dir: &'a Path,
    data: RefCell<File>,
    index: RefCell<File>,
    hashes: RefCell<Vec<File>>,
    _marker: PhantomData<T>
}

impl <'a, T:Serialize+Deserialize<'a>> FileLog<'a, T> {
    pub fn open<P: AsRef<Path>>(dir: &'a P) -> anyhow::Result<Self> {
        let dir=dir.as_ref();
        let data=OpenOptions::new().read(true).append(true).create(true).open(dir.join("data.bin"))?;
        let index=OpenOptions::new().read(true).append(true).create(true).open(dir.join("index.bin"))?;
        
        let mut ix=0;
        let mut p = dir.join(format!("hash{}.bin",ix));
        let mut hashes=vec![];
        while p.exists() {
            hashes.push(OpenOptions::new().read(true).append(true).open(p)?);
            ix+=1;
            p = dir.join(format!("hash{}.bin",ix));
        }

        Ok(Self {
            dir,
            data:RefCell::new(data), index:RefCell::new(index), hashes:RefCell::new(hashes),
            _marker: PhantomData
        })
    }

   

}

const SZ:u64=std::mem::size_of::<usize>() as u64 + std::mem::size_of::<u64>() as u64;

impl <'a, T: Serialize+DeserializeOwned> TransparentLog<'a, T> for FileLog<'a,T> {
    type LogSize = u64;
    
    fn size(&self) -> anyhow::Result<Self::LogSize> {
        Ok(self.index.borrow().metadata()?.len()/SZ)
    }

    fn get(&self, index: Self::LogSize) -> anyhow::Result<Option<MaybeOwned<T>>> {
        
        let mut index_file=self.index.borrow_mut();
        index_file.seek(SeekFrom::Start(index * SZ))?;
        let mut b1=[0_u8;std::mem::size_of::<u64>()];
        index_file.read_exact(&mut b1)?;
        let mut b2=[0_u8;std::mem::size_of::<usize>()];
        index_file.read_exact(&mut b2)?;
        
        let offset = u64::from_be_bytes(b1);
        let length:usize=usize::from_be_bytes(b2);
        let mut b3=vec![0_u8;length];
        let mut data_file=self.data.borrow_mut();
        data_file.seek(SeekFrom::Start(offset))?;
        data_file.read_exact(&mut b3)?;
        let r=rmp_serde::from_read_ref(&b3)?;
        Ok(Some(MaybeOwned::Owned(r)))
    }

    fn add(&mut self, record: T) -> anyhow::Result<Self::LogSize> {
        let mut data_file=self.data.borrow_mut();
        let offset=data_file.metadata()?.len();
        let data=rmp_serde::to_vec(&record)?;
        let length=data.len();
        data_file.seek(SeekFrom::End(0))?;
        data_file.write_all(&data)?;
        let mut index_file=self.index.borrow_mut();
        let id=index_file.metadata()?.len()/SZ;
        index_file.seek(SeekFrom::End(0))?;
        index_file.write_all(&offset.to_be_bytes())?;
        index_file.write_all(&length.to_be_bytes())?;
        Ok(id)
    }

    fn add_hash(&mut self,level: LogHeight, hash: String) -> anyhow::Result<Self::LogSize> {
        let mut hs=self.hashes.borrow_mut();

        if hs.len()<=level{
            let p = self.dir.join(format!("hash{}.bin",level));
            hs.push(OpenOptions::new().append(true).read(true).create(true).open(p)?);
        }
        let v=  hs.get_mut(level).unwrap();
        let b=hash.as_bytes();
        let l = v.metadata()?.len()/HASH_SIZE_IN_BYTES as u64;
        v.write_all(b)?;
        Ok(l)
    }

    fn get_hash(&self, level: LogHeight, index: Self::LogSize) -> anyhow::Result<MaybeOwned<String>> {
        let mut hs=self.hashes.borrow_mut();
        let v=  hs.get_mut(level).unwrap();
        v.seek(SeekFrom::Start((HASH_SIZE_IN_BYTES as u64)*index))?;
        let mut b2=[0_u8;HASH_SIZE_IN_BYTES];
        v.read_exact(&mut b2)?;
        Ok(String::from_utf8_lossy(&b2).into_owned().into())
    }
}

#[cfg(test)]
mod tests {

    use crate::tests::test_verify_tree_prefix;
    use crate::{FileLog, InMemoryLogClientBuilder};
    use crate::base::tests::*;
    use std::path::{Path, PathBuf};
    use std::fs::{create_dir, remove_dir_all};

    use serial_test::serial;
  
    fn setup() ->anyhow::Result<PathBuf>{
        let path=Path::new("./test_data");
        println!("{} {}",path.display(),path.exists());
        if path.exists(){
            remove_dir_all(&path)?;
        }
        create_dir(&path)?;
        Ok(PathBuf::from(path))
    }


    #[test]
    #[serial]
    fn file_empty() -> anyhow::Result<()>{
        let path=setup()?;
        let mut ml: FileLog<LogRecord>=FileLog::open(&path)?;
        empty(&mut ml)
    }

    #[test]
    #[serial]
    fn file_add()-> anyhow::Result<()>{
        let path=setup()?;
        let mut ml: FileLog<LogRecord>=FileLog::open(&path)?;
        add(&mut ml)
    }

    #[test]
    #[serial]
    fn file_13()-> anyhow::Result<()>{
        let path=setup()?;
        let mut ml: FileLog<LogRecord>=FileLog::open(&path)?;
        test_13(&mut ml)?;
        
        let ml: FileLog<LogRecord>=FileLog::open(&path)?;
        check_13(&ml)
    }

    #[test]
    #[serial]
    fn file_memory_13()-> anyhow::Result<()>{
        let path=setup()?;
        let mut ml: FileLog<LogRecord>=FileLog::open(&path)?;
        let mut client= InMemoryLogClientBuilder::new(&ml)?.build();
        client_13(&mut ml, &mut client)
    
    }

    #[test]
    #[serial]
    fn file_memory_13_no_cache()-> anyhow::Result<()>{
        let path=setup()?;
        let mut ml: FileLog<LogRecord>=FileLog::open(&path)?;
        let mut client= InMemoryLogClientBuilder::new(&ml)?.no_cache().build();
        client_13_nocache(&mut ml, &mut client)

    }

    
     #[test]
     #[serial]
     fn file_verify_tree_prefix()-> anyhow::Result<()>{
        let path=setup()?;
        let mut ml: FileLog<LogRecord>=FileLog::open(&path)?;
        test_verify_tree_prefix(&mut ml)

     }

}
