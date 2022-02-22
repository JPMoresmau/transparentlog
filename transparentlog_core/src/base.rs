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

    // Get the latest log size and root hash
    fn latest(&self) -> anyhow::Result<LogTree<Self::LogSize>>;

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
    use crate::{TransparentLog, tree_sizes, proof_positions, verify, prefix_proof_positions, verify_tree, hash, check_record, LogClient, Record, LogTree};
    use std::fmt::{Display,Formatter, Result};
    use crypto::{sha2::Sha256, digest::Digest};
    use num::{Zero,One};
    use std::fmt::Debug;
    use serde::{Serialize,Deserialize};
    use core::ops::Deref;

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

    
 
     #[derive(Serialize,Deserialize,Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct LogRecord {
        pub text: String,
     }
 
     impl LogRecord {
         pub fn new(s:&str) -> Self{
             LogRecord{text:String::from(s)}
         }
 
     }
 
     impl Display for LogRecord {
         fn fmt(&self, f: &mut Formatter<'_>) -> Result {
             write!(f, "{}", self.text)
         }
     }

     pub fn append_multiple<'a, T: TransparentLog<'a, LogRecord>>(log:&mut T, nb:usize) -> anyhow::Result<()>{
         append_multiple_offset(log,0,nb)
     }
 
     pub fn append_multiple_offset<'a, T: TransparentLog<'a, LogRecord>>(log:&mut T, start:usize, nb:usize) -> anyhow::Result<()>{
         for i in start..(start+nb) {
             let lr=LogRecord{text:format!("rec{}",i)};
             log.append(lr)?;
         }
         Ok(())
     }
 
     pub fn hash_two(start:usize) -> anyhow::Result<String>{
         Ok(hash_two_strings(&hash(&LogRecord{text:format!("rec{}",start)})?,&hash(&LogRecord{text:format!("rec{}",start+1)})?))
     }
 
     pub fn hash_two_strings(s1: &str, s2: &str) -> String{
         let mut hasher = Sha256::new();
         hasher.input_str(&format!("{}{}",s1,s2));
         hasher.result_str()
     }
 
     pub fn hash_four(start:usize) -> anyhow::Result<String>{
         let mut hasher = Sha256::new();
         hasher.input_str(&format!("{}{}",hash_two(start)?,hash_two(start+2)?));
         Ok(hasher.result_str())
     }
 
     pub fn hash_eight(start:usize) -> anyhow::Result<String>{
         let mut hasher = Sha256::new();
         hasher.input_str(&format!("{}{}",hash_four(start)?,hash_four(start+4)?));
         Ok(hasher.result_str())
     }
 
    pub fn empty<'a, T>(ml: &mut T) -> anyhow::Result<()>
        where T:TransparentLog<'a, LogRecord>, T::LogSize:Debug{
         let LogTree{size:s,hash:t} = ml.latest()?;
         assert_eq!(T::LogSize::zero(),s);
         assert_eq!("",&t);
         Ok(())
     }

     pub fn add<'a, T>(ml: &mut T)-> anyhow::Result<()>
     where T:TransparentLog<'a, LogRecord>, T::LogSize:Debug, T::LogSize:From<u8>{
         let lr1=LogRecord::new("rec1");
         let h1=hash(&lr1)?;
         let Record{id:ix,hash:h1s} = ml.append(lr1)?;      
         assert_eq!(T::LogSize::zero(),ix);     
         assert_eq!(h1,h1s);
         let og=ml.get(ix)?;
         assert_eq!("rec1",og.unwrap().text);
         let LogTree{size:s,hash:t} = ml.latest()?;
         assert_eq!(T::LogSize::one(),s);
         assert_eq!(h1,t);
         let lr2=LogRecord::new("rec2");
         let h2=hash(&lr2)?;
         let Record{id:ix,hash:h2s}=ml.append(lr2)?;           
         assert_eq!(Into::<T::LogSize>::into(1),ix);     
         assert_eq!(h2,h2s);
         let og=ml.get(ix)?;
         assert_eq!("rec2",og.unwrap().text);
         let LogTree{size:s,hash:t} = ml.latest()?;
         assert_eq!(Into::<T::LogSize>::into(2),s);
         let mut hasher = Sha256::new();
         hasher.input_str(&format!("{}{}",h1,h2));
         assert_eq!(hasher.result_str(),t);
         let v=ml.proofs(proof_positions::<T::LogSize>(1.into(), 2.into()).into_iter())?;
         assert_eq!(1,v.len());
         assert_eq!(v.get(&(0,0.into()).into()),Some(&hash(&LogRecord::new("rec1"))?));
         assert!(verify(&LogTree{size:s,hash:t},&Record{id:1.into(),hash:hash(&LogRecord::new("rec2"))?},&v));
         Ok(())
     }
 
    
     pub fn test_13<'a, T>(ml: &mut T)-> anyhow::Result<()>
     where T:TransparentLog<'a, LogRecord>, T::LogSize:Debug, T::LogSize:From<u8>{
         append_multiple(ml, 13)?;
         check_13(ml)
 
     }
 
     pub fn check_13<'a, T>(ml: & T)-> anyhow::Result<()>
     where T:TransparentLog<'a, LogRecord>, T::LogSize:Debug, T::LogSize:From<u8> {
        let LogTree{size:s,hash:t} = ml.latest()?;
        assert_eq!(Into::<T::LogSize>::into(13),s);
        let v=ml.proofs(proof_positions::<T::LogSize>(9.into(), 13.into()).into_iter())?;
        assert_eq!(4,v.len());
        assert_eq!(v.get(&(0,8.into()).into()),Some(&hash(&LogRecord::new("rec8"))?));
        assert_eq!(v.get(&(1,5.into()).into()),Some(&hash_two(10)?));
        assert_eq!(v.get(&(3,0.into()).into()),Some(&hash_eight(0)?));
        assert_eq!(v.get(&(0,12.into()).into()),Some(&hash(&LogRecord::new("rec12"))?));

        let mut h=hash_two_strings(v.get(&(0,8.into()).into()).unwrap(), &hash(&LogRecord::new("rec9"))?);
        h=hash_two_strings(&h,v.get(&(1,5.into()).into()).unwrap());
        h=hash_two_strings(&h, v.get(&(0,12.into()).into()).unwrap());
        h=hash_two_strings(v.get(&(3,0.into()).into()).unwrap(), &h);
        assert_eq!(t,h);

        assert!(verify(&LogTree{size:s,hash:t},&Record{id:9.into(),hash:hash(&LogRecord::new("rec9"))?},&v));
        Ok(())
     }

    pub fn client_13<'a, T, LC>(ml: &mut T, client: &mut LC)-> anyhow::Result<()>
    where T:TransparentLog<'a, LogRecord>, T::LogSize:Debug, T::LogSize:From<u8>, LC:LogClient<'a, LogRecord,T>{
         assert_eq!(T::LogSize::zero(),client.latest().size);
         assert_eq!(String::new(),client.latest().hash);
         assert!(client.cached(&(0,8.into()).into()).is_none());
         append_multiple(ml, 13)?;
         let lr=ml.get(9.into())?.unwrap();
         assert!(check_record(client, ml,&Record{id:9.into(),hash:hash(lr.deref())?})?);
         assert_eq!(Into::<T::LogSize>::into(13),client.latest().size);
         assert!(client.cached(&(0,8.into()).into()).is_some());
         Ok(())
     }
 
     pub fn client_13_nocache<'a, T, LC>(ml: &mut T, client: &mut LC)-> anyhow::Result<()>
     where T:TransparentLog<'a, LogRecord>, T::LogSize:Debug, T::LogSize:From<u8>, LC:LogClient<'a, LogRecord,T>{
          assert_eq!(T::LogSize::zero(),client.latest().size);
          assert_eq!(String::new(),client.latest().hash);
          assert!(client.cached(&(0,8.into()).into()).is_none());
          append_multiple(ml, 13)?;
          let lr=ml.get(9.into())?.unwrap();
          assert!(check_record(client, ml,&Record{id:9.into(),hash:hash(lr.deref())?})?);
          assert_eq!(Into::<T::LogSize>::into(13),client.latest().size);
          assert!(client.cached(&(0,8.into()).into()).is_none());
          Ok(())
      }
  

     pub fn test_verify_tree_prefix<'a, T>(ml: &mut T)-> anyhow::Result<()>
      where T:TransparentLog<'a, LogRecord>, T::LogSize:Debug, T::LogSize:From<u8>{
         append_multiple(ml, 7)?;
         let lt0 = ml.latest()?;
         append_multiple_offset(ml, 8,6)?;
         let lt1 = ml.latest()?;
         let v=prefix_proof_positions::<T::LogSize>(7.into(), 13.into());
         let proofs=ml.proofs(v.into_iter())?;
         assert!(verify_tree(&lt0,&proofs));
         assert!(verify_tree(&lt1,&proofs));
         Ok(())
      }
}