use std::collections::{HashMap};

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use maybe_owned::MaybeOwned;
use std::fmt::Debug;
use serde::{Serialize,Deserialize};

pub use crate::base::*;



// An in-memory transparent log
#[derive(Debug)]
pub struct InMemoryLog<T> {
    // Records are stored in a Vec
    data: Vec<T>,
    // Hashes by level in the tree
    hashes: Vec<Vec<String>>,
}

// Default implementation for an empty in-memory log
impl <T> Default for InMemoryLog<T>{
    fn default() -> Self {
        Self{data:Default::default(),hashes:Default::default()}
    }
}


// TransparentLog Trait implementation for in-memory log
impl <'a, T: Serialize+Deserialize<'a>> TransparentLog<'a, T> for InMemoryLog<T> {
    // Vec size
    type LogSize = usize;


    fn latest(&self) -> anyhow::Result<LogTree<Self::LogSize>> {
        let mut r=vec![];
        for v in self.hashes.iter().rev(){
            if v.len() % 2 == 1 {
                r.push(v[v.len()-1].clone());
            }
        }
        while r.len()>1{
            let s1=r.pop().unwrap();
            let s2=r.pop().unwrap();
            let mut hasher = Sha256::new();
            hasher.input_str(&format!("{}{}",s2,s1));
            r.push(hasher.result_str());
        }
        
        Ok(LogTree{size:self.data.len(), hash:r.pop().unwrap_or_default()})
    }

    fn get(&self, index: Self::LogSize) ->anyhow::Result<Option<MaybeOwned<T>>> {
        Ok(self.data.get(index).map(|t| t.into()))
    }

    fn add(&mut self, record: T) -> anyhow::Result<Self::LogSize> {
        let id=self.data.len();
        self.data.push(record);
        Ok(id)
    }

    fn add_hash(&mut self,level: LogHeight, hash: String) -> anyhow::Result<Self::LogSize> {
        if self.hashes.len()<=level{
            self.hashes.push(vec![]);
        }
        let v=  self.hashes.get_mut(level).unwrap();
        v.push(hash);
        Ok(v.len()-1)
    }

    fn get_hash(&self, level: LogHeight, index: Self::LogSize) -> anyhow::Result<MaybeOwned<String>> {
         Ok(self.hashes.get(level).unwrap().get(index).unwrap().into())
    } 
}

// In-memory client to a TransparentLog, keeping track of the latest log verified
pub struct InMemoryLogClient<'a, T: Serialize+Deserialize<'a>,TL: TransparentLog<'a, T>> {
    latest: LogTree<TL::LogSize>,

    cache: Option<HashMap<LogTreePosition<TL::LogSize>,String>>,
}

// Build an in-memory client, from the current state of the log or a saved state
pub struct InMemoryLogClientBuilder<'a, T: Serialize+Deserialize<'a>,TL: TransparentLog<'a, T>>{
    latest: LogTree<TL::LogSize>,
    cache: bool,
}

impl <'a, T: Serialize+Deserialize<'a>,TL: TransparentLog<'a, T>> InMemoryLogClientBuilder<'a, T,TL>{
    pub fn new(log: &TL) -> anyhow::Result<Self> {
        let latest=log.latest()?;
        Ok(Self {
            latest,
            cache: true,
        })
    }

    pub fn open(latest: LogTree<TL::LogSize>) -> Self {
        Self{latest,cache: true,}
    }
    
    // Client caches positions by default, disable if needed
    pub fn no_cache<>(&mut self) -> &mut Self {
        self.cache=false;
        self
    }

    pub fn build(&self) -> InMemoryLogClient<'a, T,TL>{
        InMemoryLogClient{latest:LogTree{size:self.latest.size,hash:self.latest.hash.clone()}, 
            cache:if self.cache{
                Some(HashMap::new())
            } else {
                None
            }}
    }
}


impl <'a, T: Serialize+Deserialize<'a>,TL: TransparentLog<'a, T>> LogClient<'a, T,TL> for InMemoryLogClient<'a, T,TL> {
    fn latest(&self) -> &LogTree<TL::LogSize> {
        &self.latest
    }

    fn set_latest(&mut self, latest: LogTree<TL::LogSize>) {
        self.latest=latest
    }

    fn cached(&self, position: &LogTreePosition<TL::LogSize>) -> Option<String> {
        if let Some(m) = &self.cache {
            return m.get(position).cloned()
        }
        None
    }

    fn add_cached(&mut self, proofs: &HashMap<LogTreePosition<TL::LogSize>,String>) {
        if let Some(m) = self.cache.as_mut() {
            m.extend(proofs.clone());
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::tests::test_verify_tree_prefix;
    use crate::{InMemoryLog, InMemoryLogClientBuilder};
    use crate::base::tests::*;

    #[test]
    fn memory_empty() -> anyhow::Result<()>{
        let mut ml: InMemoryLog<LogRecord>=InMemoryLog::default();
        empty(&mut ml)
    }

    #[test]
    fn memory_add()-> anyhow::Result<()>{
        let mut ml: InMemoryLog<LogRecord>=InMemoryLog::default();
        add(&mut ml)
    }

    #[test]
    fn memory_13()-> anyhow::Result<()>{
        let mut ml: InMemoryLog<LogRecord>=InMemoryLog::default();
        test_13(&mut ml)
        
    }

    #[test]
    fn client_memory_13()-> anyhow::Result<()>{
        let mut ml: InMemoryLog<LogRecord>=InMemoryLog::default();
        let mut client= InMemoryLogClientBuilder::new(&ml)?.build();
        client_13(&mut ml, &mut client)
    
    }

    #[test]
    fn client_memory_13_no_cache()-> anyhow::Result<()>{
        let mut ml: InMemoryLog<LogRecord>=InMemoryLog::default();
        let mut client= InMemoryLogClientBuilder::new(&ml)?.no_cache().build();
        client_13_nocache(&mut ml, &mut client)

    }

    
     #[test]
     fn memory_verify_tree_prefix()-> anyhow::Result<()>{
        let mut ml: InMemoryLog<LogRecord>=InMemoryLog::default();
        test_verify_tree_prefix(&mut ml)

     }

}
