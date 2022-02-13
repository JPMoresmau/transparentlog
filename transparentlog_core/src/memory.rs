use std::collections::{HashMap};

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use maybe_owned::MaybeOwned;
use std::fmt::Debug;

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


// Internal method
impl <T> InMemoryLog<T> {
    fn push_hash(&mut self, level: LogHeight, hash: String){
        if self.hashes.len()<=level{
            self.hashes.push(vec![]);
        }
        let v=  self.hashes.get_mut(level).unwrap();
        v.push(hash);
        let l = v.len();
        if l % 2 ==0 {
            let mut hasher = Sha256::new();
            hasher.input_str(&format!("{}{}",v[l-2],v[l-1]));
            self.push_hash(level+1, hasher.result_str());
        }
    }

}

// TransparentLog Trait implementation for in-memory log
impl <T> TransparentLog<T> for InMemoryLog<T> {
    // Vec size
    type LogSize = usize;

    fn append(&mut self, record: T, hash: String) -> anyhow::Result<Self::LogSize>{
     
        self.data.push(record);

        self.push_hash(0, hash);
       
        Ok(self.data.len())
    }

    fn latest(&self) -> anyhow::Result<(Self::LogSize,String)> {
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
        
        Ok((self.data.len(), r.pop().unwrap_or_default()))
    }

    fn get(&self, index: Self::LogSize) ->anyhow::Result<Option<MaybeOwned<T>>> {
        Ok(self.data.get(index).map(|t| t.into()))
    }

    fn proofs<I>(&self, positions: I) -> anyhow::Result<HashMap<(LogHeight,Self::LogSize),String>>
    where I: Iterator<Item=(LogHeight,Self::LogSize)> {
        Ok(positions.map(|(r,i)| ((r,i),self.hashes[r][i].clone())).collect())
    } 
}

// In-memory client to a TransparentLog, keeping track of the latest log verified
pub struct InMemoryLogClient<T,TL: TransparentLog<T>> {
    latest: (TL::LogSize,String),

    cache: Option<HashMap<(LogHeight,TL::LogSize),String>>,
}

// Build an in-memory client, from the current state of the log or a saved state
pub struct InMemoryLogClientBuilder<T,TL: TransparentLog<T>>{
    latest: (TL::LogSize,String),
    cache: bool,
}

impl <T,TL: TransparentLog<T>> InMemoryLogClientBuilder<T,TL>{
    pub fn new(log: &TL) -> anyhow::Result<Self> {
        let latest=log.latest()?;
        Ok(Self {
            latest,
            cache: true,
        })
    }

    pub fn open(latest: (TL::LogSize,String)) -> Self {
        Self{latest,cache: true,}
    }
    
    // Client caches positions by default, disable if needed
    pub fn no_cache<'a>(&'a mut self) -> &'a mut Self {
        self.cache=false;
        self
    }

    pub fn build(&self) -> InMemoryLogClient<T,TL>{
        InMemoryLogClient{latest:self.latest.clone(), 
            cache:if self.cache{
                Some(HashMap::new())
            } else {
                None
            }}
    }
}


impl <T,TL: TransparentLog<T>> LogClient<T,TL> for InMemoryLogClient<T,TL> {
    fn latest(&self) -> &(TL::LogSize,String) {
        &self.latest
    }

    fn set_latest(&mut self, latest: (TL::LogSize,String)) {
        self.latest=latest
    }

    fn cached(&self, position: &(LogHeight,TL::LogSize)) -> Option<String> {
        if let Some(m) = &self.cache {
            return m.get(position).cloned()
        }
        None
    }

    fn add_cached(&mut self, proofs: &HashMap<(LogHeight,TL::LogSize),String>) {
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
