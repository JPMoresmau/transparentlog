use std::{collections::{HashMap,HashSet}, ops::Add};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use maybe_owned::MaybeOwned;
use num::{Integer,Zero, One};
use std::hash::Hash;

use serde::{Serialize,Deserialize};

pub type LogHeight = usize;

// Reference to a Record, with its ID and its hash
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct Record<LogSize> {
    pub id: LogSize,
    pub hash: String,
}

// Position in the tree
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct LogTreePosition<LogSize> {
    pub level: LogHeight,
    pub index: LogSize,
}

impl <LogSize> From<(LogHeight,LogSize)> for LogTreePosition<LogSize> {
    fn from((level,index): (LogHeight,LogSize)) -> Self {
        Self{level,index}
    }
}


// Reference to a full log: its size and root hash
pub struct LogTree<LogSize>{
    pub size: LogSize,
    pub hash: String,
}



// Transparent log Trait
pub trait TransparentLog<'a, T: Serialize+Deserialize<'a>> {
    // The type used to represent the log size
    type LogSize: Integer + Copy + Hash;

    // Add a record, return the record ID
    fn add(&mut self, record: T) -> anyhow::Result<Self::LogSize>;

    // Add a hash and index, returns the index of the added hash
    fn add_hash(&mut self,level: LogHeight, hash: String) -> anyhow::Result<Self::LogSize>;

    // Get a hash at the given level and index
    fn get_hash(&self, level: LogHeight, index: Self::LogSize) -> anyhow::Result<MaybeOwned<String>>;

    // Append a new record to the log and return its index
    //fn append(&mut self, record: T) -> anyhow::Result<Record<Self::LogSize>>;
    fn append(&mut self, record: T) -> anyhow::Result<Record<Self::LogSize>>{
        let hash= hash(&record)?;
        let id=self.add(record)?;
        self.push_hash(0, hash.clone())?;
        Ok(Record{id,hash})
    }

    // Recursively push a hash to the tree at given level
    fn push_hash(&mut self, level: LogHeight, hash: String)-> anyhow::Result<Self::LogSize>{
        let hid=self.add_hash(level,hash.clone())?;
        let two=Self::LogSize::one().add(Self::LogSize::one());
        if hid.mod_floor(&two) == Self::LogSize::one() {
            let mut hasher = Sha256::new();
            let hash1=self.get_hash(level,hid-Self::LogSize::one())?;
            hasher.input_str(&format!("{}{}",hash1,hash));
            self.push_hash(level+1, hasher.result_str())?;
        }
        Ok(hid)
    }

    fn size(&self) -> anyhow::Result<Self::LogSize>;

    // Get the latest log size and root hash
    fn latest(&self) -> anyhow::Result<LogTree<Self::LogSize>>{
        let sz= self.size()?;
        let two=Self::LogSize::one().add(Self::LogSize::one());
        let mut r=vec![];

        for (level,size) in tree_sizes(sz).into_iter().enumerate().rev(){
            if size.mod_floor(&two) == Self::LogSize::one() {
                r.push(self.get_hash(level,size-Self::LogSize::one())?)
            }
        }

        while r.len()>1{
            let s1=r.pop().unwrap();
            let s2=r.pop().unwrap();
            let mut hasher = Sha256::new();
            hasher.input_str(&format!("{}{}",s2,s1));
            r.push(MaybeOwned::Owned(hasher.result_str()));
        }
        
        Ok(LogTree{size:sz, hash:r.pop().unwrap_or_default().into_owned()})
    }

    // Retrieve a log entry by its index
    fn get(&self, index: Self::LogSize) -> anyhow::Result<Option<MaybeOwned<T>>>;

    // Return the requested proofs from the log
    fn proofs<I>(&self, positions: I) -> anyhow::Result<HashMap<LogTreePosition<Self::LogSize>,String>>
        where I: Iterator<Item=LogTreePosition<Self::LogSize>> {
        positions.map(|p| {
            let hash=self.get_hash(p.level,p.index)?.into_owned();
            Ok((p,hash))}
        ).collect()
    }
}






pub trait LogClient<'a, T: Serialize+Deserialize<'a>,TL: TransparentLog<'a,T>> {
    fn latest(&self) -> &LogTree<TL::LogSize>;

    fn set_latest(&mut self, latest: LogTree<TL::LogSize>);

    fn cached(&self, position: &LogTreePosition<TL::LogSize>) -> Option<String>;
    
    fn add_cached(&mut self, proofs: &HashMap<LogTreePosition<TL::LogSize>,String>);
}



// Check a given index + hash is contained in the given log, using the stored latest verification if possible or updating the cache if needed
pub fn check_record<'a, T: Serialize+Deserialize<'a>,TL: TransparentLog<'a, T>,LC: LogClient<'a, T,TL>> (client: &mut LC, log: &TL, record: &Record<TL::LogSize>) -> anyhow::Result<bool> {
    if record.id>=client.latest().size {
        let l2=log.latest()?;
         
        if client.latest().size>TL::LogSize::zero(){
            let v=prefix_proof_positions(client.latest().size, l2.size);
            let proofs=get_proofs(client,log,v)?;
            if !verify_tree(client.latest(),&proofs){
                return Ok(false);
            }
            if !verify_tree(&l2,&proofs){
                return Ok(false);
            }
        }
        client.set_latest(l2);
    }
   let v= proof_positions(record.id,client.latest().size);
   let proofs=get_proofs(client,log,v)?;
   Ok(verify(client.latest(),record,&proofs))
}

fn get_proofs<'a, T: Serialize+Deserialize<'a>,TL: TransparentLog<'a, T>,LC: LogClient<'a, T,TL>>(client: &mut LC, log: &TL,positions: HashSet<LogTreePosition<TL::LogSize>>)
    -> anyhow::Result<HashMap<LogTreePosition<TL::LogSize>,String>> {
    let mut cached:HashMap<LogTreePosition<TL::LogSize>,String>=HashMap::new();
    let read = log.proofs(positions.into_iter().filter(|p| {
        if let Some (h) = client.cached(p){
            cached.insert(p.clone(),h);
            return false;
        }
        true
    }))?;
    client.add_cached(&read);
    if cached.is_empty(){
        Ok(read)
    } else {
        cached.extend(read.into_iter());
        Ok(cached)
    }
}

// Hash a given record via its Display instance
pub fn hash<T:Serialize>(record: &T) -> anyhow::Result<String> {
    let mut hasher = Sha256::new();
    hasher.input(&rmp_serde::to_vec(record)?);
    Ok(hasher.result_str())
}

// Return the level sizes for each level of the tree
pub fn tree_sizes<LogSize: Integer + Copy>(size: LogSize) -> Vec<LogSize> {
    let mut v=vec![];
    let mut sz=size;
    let mut height=LogSize::one();
    let two=LogSize::one().add(LogSize::one());
    if sz>LogSize::zero() {
        v.push(sz);
        while height<size && sz>LogSize::zero(){
            if sz.is_one(){
                sz=LogSize::zero();
            } else {
                sz=sz.div(two);
            }
            v.push(sz);
            height=height*two;
        }
        
    }

    v
}

// Calculate the proof position needed to assert the record at the given index is present in a log of the given size
pub fn proof_positions<LogSize: Integer + Copy + Hash>(index: LogSize, size: LogSize) -> HashSet<LogTreePosition<LogSize>>{
    let sizes=tree_sizes(size);
    let mut proof=HashSet::new();
    if sizes.is_empty(){
        return proof;
    }
    proof_step(0, index, size, &sizes, &mut proof);
    proof
}

// Calculate one level of proof
fn proof_step<LogSize: Integer + Copy + Hash>(level: LogHeight, index: LogSize, size: LogSize, sizes: &[LogSize], proof: &mut HashSet<LogTreePosition<LogSize>>) {
    let two=LogSize::one().add(LogSize::one());
    if index.mod_floor(&two).is_zero() {
        if index+LogSize::one()<size{
            proof.insert(LogTreePosition{level,index:index +LogSize::one()});
        } else {
            let mut new_level=level;
            let mut new_index=index+LogSize::one();
            while new_level>0 {
                new_level-=1;
                new_index=new_index*two;
                if (new_index as LogSize) < sizes[new_level]{
                    proof.insert(LogTreePosition{level:new_level,index:new_index as LogSize});
                    break;
                }
            }
        }
    } else {
        proof.insert(LogTreePosition{level,index:index - LogSize::one()});
    }
    if level<sizes.len()-1{
        proof_step(level+1, index/two, size/two, sizes, proof);
    }
}

// Calculate the proof positions needed to assert a tree of size1 is a prefix of a tree of size 2
pub fn prefix_proof_positions<LogSize: Integer + Copy + Hash>(size1: LogSize, size2: LogSize) -> HashSet<LogTreePosition<LogSize>>{
    assert!(size1>LogSize::zero());
    assert!(size1<size2);

    let mut proof = proof_positions(size1,size2);
    proof.extend(proof_positions(size1-LogSize::one(),size2));
    let two=LogSize::one().add(LogSize::one());
    let sizes2=tree_sizes(size2);
    let m=sizes2.len()-1;
    for (ix,sz) in sizes2.into_iter().enumerate() {
        if ix<m && sz.mod_floor(&two).is_one() {
            proof.insert(LogTreePosition{level:ix,index:sz-LogSize::one()});
            break;
        }
    }
    proof
}

// Verify that a given record belongs to the given tree, using the proofs provided
pub fn verify<LogSize: Integer + Copy + Hash>(tree:&LogTree<LogSize>,record:&Record<LogSize>, proofs: &HashMap<LogTreePosition<LogSize>,String>) -> bool {
    let sizes=tree_sizes(tree.size);
    if sizes.is_empty(){
        return false;
    }
    let mut proofs2=proofs.clone();
    proofs2.insert(LogTreePosition{level:0,index:record.id},record.hash.clone());
    tree.hash==calc_hash(LogTreePosition{level:sizes.len()-1,index:LogSize::zero()},&proofs2,&sizes)
}

// Verify that the tree is correct with the proofs provided
pub fn verify_tree<LogSize: Integer + Copy + Hash>(tree:&LogTree<LogSize>, proofs: &HashMap<LogTreePosition<LogSize>,String>) -> bool {
    let sizes=tree_sizes(tree.size);
    if sizes.is_empty(){
        return false;
    }
    tree.hash==calc_hash(LogTreePosition{level:sizes.len()-1,index:LogSize::zero()},proofs,&sizes)
}

// Calculate the hash of a given level or index, recursively going down the tree
fn calc_hash<LogSize: Integer + Copy + Hash>(position: LogTreePosition<LogSize>, proofs: &HashMap<LogTreePosition<LogSize>,String>, sizes: &[LogSize]) -> String{
    if position.index<sizes[position.level] {
        if let Some(h) = proofs.get(&position){
            return h.clone();
        }
    }
    if position.level>0{
        let two=LogSize::one().add(LogSize::one());
        let new_index=position.index * two;
        let h1=calc_hash(LogTreePosition{level:position.level-1,index:new_index},proofs,sizes);
        let h2=calc_hash(LogTreePosition{level:position.level-1,index:new_index+LogSize::one()},proofs,sizes);
        if h2.is_empty(){
            return h1;
        }
        let mut hasher = Sha256::new();
        hasher.input_str(&format!("{}{}",h1,h2));
        return hasher.result_str();
    }
    String::new()
}


#[cfg(test)]
pub mod tests {
    use crate::{ tree_sizes, proof_positions, prefix_proof_positions};


    #[test]
    fn test_tree_sizes(){
        assert!(tree_sizes(0_u64).is_empty());
        assert_eq!(vec![1],tree_sizes(1_u64));
        assert_eq!(vec![2,1],tree_sizes(2_u64));
        assert_eq!(vec![3,1,0],tree_sizes(3_u64));
        assert_eq!(vec![4,2,1],tree_sizes(4_u64));
        assert_eq!(vec![5,2,1,0],tree_sizes(5_u64));
        assert_eq!(vec![6,3,1,0],tree_sizes(6_u64));
        assert_eq!(vec![7,3,1,0],tree_sizes(7_u64));
        assert_eq!(vec![8,4,2,1],tree_sizes(8_u64));
        assert_eq!(vec![9,4,2,1,0],tree_sizes(9_u64));
        assert_eq!(vec![10,5,2,1,0],tree_sizes(10_u64));
        assert_eq!(vec![11,5,2,1,0],tree_sizes(11_u64));
        assert_eq!(vec![12,6,3,1,0],tree_sizes(12_u64));
        assert_eq!(vec![13,6,3,1,0],tree_sizes(13_u64));
        assert_eq!(vec![14,7,3,1,0],tree_sizes(14_u64));
        assert_eq!(vec![15,7,3,1,0],tree_sizes(15_u64));
        assert_eq!(vec![16,8,4,2,1],tree_sizes(16_u64));
    }

    #[test]
    fn test_proof_positions(){
        assert!(proof_positions(0_u64,0).is_empty());
        let v=proof_positions(9_u64, 13);
        assert_eq!(4,v.len());
        assert!(v.contains(&(0,8).into()));
        assert!(v.contains(&(1,5).into()));
        assert!(v.contains(&(3,0).into()));
        assert!(v.contains(&(0,12).into()));
        let v=proof_positions(7, 8);
        assert_eq!(3,v.len());
        assert!(v.contains(&(0,6).into()));
        assert!(v.contains(&(1,2).into()));
        assert!(v.contains(&(2,0).into()));
        let v=proof_positions(12, 13);
        assert_eq!(2,v.len());
        assert!(v.contains(&(3,0).into()));
        assert!(v.contains(&(2,2).into()));

        let v=proof_positions(9, 16);
        assert_eq!(4,v.len());
        assert!(v.contains(&(3,0).into()));
        assert!(v.contains(&(2,3).into()));
        assert!(v.contains(&(1,5).into()));
        assert!(v.contains(&(0,8).into()));
     }
  
     #[test]
     fn test_prefix_proof_positions(){
        let v=prefix_proof_positions(7_u64, 13);
        //println!("{:?}",v);
        assert_eq!(6,v.len());
        assert!(v.contains(&(2,0).into()));
        assert!(v.contains(&(1,2).into()));
        assert!(v.contains(&(0,6).into()));
        assert!(v.contains(&(0,7).into()));
        assert!(v.contains(&(0,12).into()));
        assert!(v.contains(&(2,2).into()));

        let v=prefix_proof_positions(7_u64, 16);
        //println!("{:?}",v);
        assert_eq!(5,v.len());
        assert!(v.contains(&(2,0).into()));
        assert!(v.contains(&(1,2).into()));
        assert!(v.contains(&(0,6).into()));
        assert!(v.contains(&(0,7).into()));
        assert!(v.contains(&(3,1).into()));
     }

    
}