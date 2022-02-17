use std::collections::{HashMap};
use std::marker::PhantomData;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use maybe_owned::MaybeOwned;
use std::fmt::Debug;
use std::path::Path;
use std::fs::{File, OpenOptions};
use std::io::{Result, SeekFrom};
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
    pub fn open<P: AsRef<Path>>(dir: &'a P) -> Result<Self> {
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
            dir: dir.clone(),
            data:RefCell::new(data), index:RefCell::new(index), hashes:RefCell::new(hashes),
            _marker: PhantomData
        })
    }

   

}

fn push_hash(dir: &Path, hs: &mut Vec<File>, level: LogHeight, hash: &str) ->anyhow::Result<()>{

    if hs.len()<=level{
        let p = dir.join(format!("hash{}.bin",level));
        hs.push(OpenOptions::new().append(true).read(true).create(true).open(p)?);
    }
    let v=  hs.get_mut(level).unwrap();
    
    let b=hash.as_bytes();
    //println!("Size of array: {}",b.len());
    v.write_all(b)?;
    let l = v.metadata()?.len()/b.len() as u64;
    if l % 2 ==0 {
        v.seek(SeekFrom::End(- (HASH_SIZE_IN_BYTES as i64)*2))?;
        let mut b2=[0_u8;HASH_SIZE_IN_BYTES];
        v.read_exact(&mut b2)?;
        let mut hasher = Sha256::new();
        hasher.input_str(&format!("{}{}",String::from_utf8_lossy(&b2),hash));
        push_hash(dir, hs, level+1, &hasher.result_str())?;
    }
    Ok(())
}

const SZ:u64=std::mem::size_of::<usize>() as u64 + std::mem::size_of::<u64>() as u64;

impl <'a, T: Serialize+DeserializeOwned> TransparentLog<'a, T> for FileLog<'a,T> {
    // Vec size
    type LogSize = u64;

    fn append(&mut self, record: T) -> anyhow::Result<(Self::LogSize,String)>{ 
        let hash= hash(&record)?;
       
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

                
        let mut hs=self.hashes.borrow_mut();
        push_hash(self.dir, &mut hs, 0, &hash)?;

        Ok((id,hash))
    }

    fn latest(&self) -> anyhow::Result<(Self::LogSize,String)> {
        let sz=self.index.borrow().metadata()?.len()/SZ;
        let mut r=vec![];
        for v in self.hashes.borrow_mut().iter_mut().rev(){
            println!("Size: {}",v.metadata()?.len());
            let len=v.metadata()?.len()/HASH_SIZE_IN_BYTES as u64;
            if len % 2 == 1 {
                v.seek(SeekFrom::End(- (HASH_SIZE_IN_BYTES as i64)))?;
                let mut b2=[0_u8;HASH_SIZE_IN_BYTES];
                v.read_exact(&mut b2)?;
                r.push(String::from_utf8_lossy(&b2).into_owned());
            }
        }
        while r.len()>1{
            let s1=r.pop().unwrap();
            let s2=r.pop().unwrap();
            let mut hasher = Sha256::new();
            hasher.input_str(&format!("{}{}",s2,s1));
            r.push(hasher.result_str());
        }

        Ok((sz,r.pop().unwrap_or_default()))
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

    fn proofs<I>(&self, positions: I) -> anyhow::Result<HashMap<(LogHeight,Self::LogSize),String>>
    where I: Iterator<Item=(LogHeight,Self::LogSize)> {
        let mut m=HashMap::new();
        let mut hashes=self.hashes.borrow_mut();
        for (r,i) in positions {
            if let Some(f)=hashes.get_mut(r){
                f.seek(SeekFrom::Start(i*HASH_SIZE_IN_BYTES as u64))?;
                let mut b=vec![0_u8;HASH_SIZE_IN_BYTES];
                f.read_exact(&mut b)?;
                m.insert((r,i),String::from_utf8_lossy(&b).into_owned());
            }
        }
     
        Ok(m)
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
