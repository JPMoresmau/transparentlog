use std::collections::{HashMap,HashSet};
use std::fmt::{Display};

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use num::Integer;
use std::hash::Hash;
use std::fmt::Debug;
type LogHeight = usize;
//type LogSize = u64;


pub trait TransparentLog<T> {
    type LogSize: Integer;

    fn append(&mut self, record: T) -> Self::LogSize;

    fn latest(&self) -> (Self::LogSize,String);

    //fn record_proof(&self, index: Self::LogSize, size: Self::LogSize) -> HashMap<(LogHeight,Self::LogSize),String>;

    fn get(&self, index: Self::LogSize) -> Option<&T>;

    fn proofs<I>(&self, positions: I) -> HashMap<(LogHeight,Self::LogSize),String>
        where I: Iterator<Item=(LogHeight,Self::LogSize)>;
}

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

pub fn proof_positions<LogSize: Integer + Copy + Hash>(index: LogSize, size: LogSize) -> HashSet<(LogHeight,LogSize)>{
    let sizes=tree_sizes(size);
    let mut proof=HashSet::new();
    if sizes.is_empty(){
        return proof;
    }
    proof_step(0, index, size, &sizes, &mut proof);
    proof
}

fn proof_step<LogSize: Integer + Copy + Hash>(level: LogHeight, index: LogSize, size: LogSize, sizes: &[LogSize], proof: &mut HashSet<(LogHeight,LogSize)>) {
    let two=LogSize::one().add(LogSize::one());
    if index.mod_floor(&two).is_zero() {
        if index+LogSize::one()<size{
            proof.insert((level,index +LogSize::one()));
        } else {
            let mut new_level=level;
            let mut new_index=index+LogSize::one();
            while new_level>0 {
                new_level-=1;
                new_index=new_index*two;
                if (new_index as LogSize) < sizes[new_level]{
                    proof.insert((new_level,new_index as LogSize));
                    break;
                }
            }
        }
    } else {
        proof.insert((level,index - LogSize::one()));
    }
    if level<sizes.len()-1{
        proof_step(level+1, index/two, size/two, sizes, proof);
    }
}

pub fn prefix_proof_positions<LogSize: Integer + Copy + Hash>(size1: LogSize, size2: LogSize) -> HashSet<(LogHeight,LogSize)>{
    assert!(size1>LogSize::zero());
    assert!(size1<size2);

    let mut proof = proof_positions(size1,size2);
    proof.extend(&proof_positions(size1-LogSize::one(),size2));
    let two=LogSize::one().add(LogSize::one());
    let sizes2=tree_sizes(size2);
    let m=sizes2.len()-1;
    for (ix,sz) in sizes2.into_iter().enumerate() {
        if ix<m && sz.mod_floor(&two).is_one() {
            proof.insert((ix,sz-LogSize::one()));
            break;
        }
    }
    proof
}

pub fn verify<LogSize: Integer + Copy + Hash>(tree:&(LogSize,String),record:&(LogSize,String), proofs: &HashMap<(LogHeight,LogSize),String>) -> bool {
    let sizes=tree_sizes(tree.0);
    if sizes.is_empty(){
        return false;
    }
    let mut proofs2=proofs.clone();
    proofs2.insert((0,record.0),record.1.clone());
    tree.1==add_hash(sizes.len()-1,LogSize::zero(),&proofs2,&sizes)
}


pub fn verify_tree<LogSize: Integer + Copy + Hash + Debug>(tree:&(LogSize,String), proofs: &HashMap<(LogHeight,LogSize),String>) -> bool {
    let sizes=tree_sizes(tree.0);
    if sizes.is_empty(){
        return false;
    }
    tree.1==add_hash(sizes.len()-1,LogSize::zero(),proofs,&sizes)
}

fn add_hash<LogSize: Integer + Copy + Hash>(level: LogHeight, index: LogSize, proofs: &HashMap<(LogHeight,LogSize),String>, sizes: &[LogSize]) -> String{
    if index<sizes[level] {
        if let Some(h) = proofs.get(&(level,index)){
            return h.clone();
        }
    }
    if level>0{
        let two=LogSize::one().add(LogSize::one());
        let new_index=index * two;
        let h1=add_hash(level-1,new_index,proofs,sizes);
        let h2=add_hash(level-1,new_index+LogSize::one(),proofs,sizes);
        if h2.is_empty(){
            return h1;
        }
        let mut hasher = Sha256::new();
        hasher.input_str(&format!("{}{}",h1,h2));
        return hasher.result_str();
    }
    String::new()
}

#[derive(Debug)]
struct InMemoryLog<T> {
    data: Vec<T>,
    hashes: Vec<Vec<String>>,
}

impl <T> Default for InMemoryLog<T>{
    fn default() -> Self {
        Self{data:Default::default(),hashes:Default::default()}
    }
}



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

impl <T:Display> TransparentLog<T> for InMemoryLog<T> {
    type LogSize = usize;

    fn append(&mut self, record: T) -> Self::LogSize{
        
        let mut hasher = Sha256::new();
        hasher.input_str(&format!("{}",record));

        self.data.push(record);

        self.push_hash(0, hasher.result_str());
       
        self.data.len()
    }

    fn latest(&self) -> (Self::LogSize,String) {
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
        
        (self.data.len(), r.pop().unwrap_or_default())
    }

    fn get(&self, index: Self::LogSize) -> Option<&T> {
        self.data.get(index)
    }

    fn proofs<I>(&self, positions: I) -> HashMap<(LogHeight,Self::LogSize),String>
    where I: Iterator<Item=(LogHeight,Self::LogSize)> {
        positions.map(|(r,i)| ((r,i),self.hashes[r][i].clone())).collect()
    } 
}

#[cfg(test)]
mod tests {
    use crypto::{sha2::Sha256, digest::Digest};
    
    use crate::{InMemoryLog, TransparentLog, tree_sizes, proof_positions, verify, prefix_proof_positions, verify_tree};
    use std::fmt::{Display,Formatter, Result};

    struct LogRecord {
        text: String,
    }

    impl LogRecord {
        pub fn new(s:&str) -> Self{
            LogRecord{text:String::from(s)}
        }

        pub fn calc_hash(&self) -> String {
            let mut hasher = Sha256::new();
            hasher.input_str(&format!("{}",self));
            hasher.result_str()
        }
        
    }

    impl Display for LogRecord {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            write!(f, "{}", self.text)
        }
    }

    fn append_multiple<T: TransparentLog<LogRecord>>(log:&mut T, nb:usize){
        append_multiple_offset(log,0,nb);
    }

    fn append_multiple_offset<T: TransparentLog<LogRecord>>(log:&mut T, start:usize, nb:usize){
        for i in start..(start+nb) {
            log.append(LogRecord{text:format!("rec{}",i)});
        }
    }

    fn hash_two(start:usize) -> String{
        hash_two_strings(&LogRecord{text:format!("rec{}",start)}.calc_hash(),&LogRecord{text:format!("rec{}",start+1)}.calc_hash())
    }

    fn hash_two_strings(s1: &str, s2: &str) -> String{
        let mut hasher = Sha256::new();
        hasher.input_str(&format!("{}{}",s1,s2));
        hasher.result_str()
    }

    fn hash_four(start:usize) -> String{
        let mut hasher = Sha256::new();
        hasher.input_str(&format!("{}{}",hash_two(start),hash_two(start+2)));
        hasher.result_str()
    }

    fn hash_eight(start:usize) -> String{
        let mut hasher = Sha256::new();
        hasher.input_str(&format!("{}{}",hash_four(start),hash_four(start+4)));
        hasher.result_str()
    }

    //fn get_proof<LogSize:Integer>(v: &[(LogHeight,LogSize,String)], h: LogHeight, i: LogSize) -> &str {
    //    v.iter().find(|(r,ix,_)| *r==h && *ix==i).map(|t| &t.2).unwrap()
    //}

    #[test]
    fn memory_empty() {
        let ml: InMemoryLog<LogRecord>=InMemoryLog::default();
        let (s,t) = ml.latest();
        assert_eq!(0,s);
        assert_eq!("",&t);
    }

    #[test]
    fn memory_add(){
        let mut ml: InMemoryLog<LogRecord>=InMemoryLog::default();
        let lr1=LogRecord::new("rec1");
        let h1=lr1.calc_hash();
        ml.append(lr1);           
        let (s,t) = ml.latest();
        assert_eq!(1,s);
        assert_eq!(h1,t);
        let lr2=LogRecord::new("rec2");
        let h2=lr2.calc_hash();
        ml.append(lr2);           
        let (s,t) = ml.latest();
        assert_eq!(2,s);
        let mut hasher = Sha256::new();
        hasher.input_str(&format!("{}{}",h1,h2));
        assert_eq!(hasher.result_str(),t);
        let v=ml.proofs(proof_positions(1, 2).into_iter());
        assert_eq!(1,v.len());
        assert_eq!(v.get(&(0,0)),Some(&LogRecord::new("rec1").calc_hash()));
        assert!(verify(&(s,t),&(1,LogRecord::new("rec2").calc_hash()),&v));
    }

    #[test]
    fn memory_13(){
        let mut ml: InMemoryLog<LogRecord>=InMemoryLog::default();
        append_multiple(&mut ml, 13);
        let (s,t) = ml.latest();
        assert_eq!(13,s);
        let v=ml.proofs(proof_positions(9, 13).into_iter());
        assert_eq!(4,v.len());
        assert_eq!(v.get(&(0,8)),Some(&LogRecord::new("rec8").calc_hash()));
        assert_eq!(v.get(&(1,5)),Some(&hash_two(10)));
        assert_eq!(v.get(&(3,0)),Some(&hash_eight(0)));
        assert_eq!(v.get(&(0,12)),Some(&LogRecord::new("rec12").calc_hash()));

        let mut h=hash_two_strings(v.get(&(0,8)).unwrap(), &LogRecord::new("rec9").calc_hash());
        h=hash_two_strings(&h,v.get(&(1,5)).unwrap());
        h=hash_two_strings(&h, v.get(&(0,12)).unwrap());
        h=hash_two_strings(v.get(&(3,0)).unwrap(), &h);
        assert_eq!(t,h);

        assert!(verify(&(s,t),&(9,LogRecord::new("rec9").calc_hash()),&v));

    }

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
        assert!(proof_positions(0,0).is_empty());
        let v=proof_positions(9, 13);
        assert_eq!(4,v.len());
        assert!(v.contains(&(0,8)));
        assert!(v.contains(&(1,5)));
        assert!(v.contains(&(3,0)));
        assert!(v.contains(&(0,12)));
        let v=proof_positions(7, 8);
        assert_eq!(3,v.len());
        assert!(v.contains(&(0,6)));
        assert!(v.contains(&(1,2)));
        assert!(v.contains(&(2,0)));
        let v=proof_positions(12, 13);
        assert_eq!(2,v.len());
        assert!(v.contains(&(3,0)));
        assert!(v.contains(&(2,2)));

        let v=proof_positions(9, 16);
        assert_eq!(4,v.len());
        assert!(v.contains(&(3,0)));
        assert!(v.contains(&(2,3)));
        assert!(v.contains(&(1,5)));
        assert!(v.contains(&(0,8)));
     }
  
     #[test]
     fn test_prefix_proof_positions(){
        let v=prefix_proof_positions(7, 13);
        println!("{:?}",v);
        assert_eq!(6,v.len());
        assert!(v.contains(&(2,0)));
        assert!(v.contains(&(1,2)));
        assert!(v.contains(&(0,6)));
        assert!(v.contains(&(0,7)));
        assert!(v.contains(&(0,12)));
        assert!(v.contains(&(2,2)));

        let v=prefix_proof_positions(7, 16);
        println!("{:?}",v);
        assert_eq!(5,v.len());
        assert!(v.contains(&(2,0)));
        assert!(v.contains(&(1,2)));
        assert!(v.contains(&(0,6)));
        assert!(v.contains(&(0,7)));
        assert!(v.contains(&(3,1)));
     }

     #[test]
     fn test_verify_tree_prefix(){
        let mut ml: InMemoryLog<LogRecord>=InMemoryLog::default();
        append_multiple(&mut ml, 7);
        let (s0,t0) = ml.latest();
        append_multiple_offset(&mut ml, 8,6);
        let (s1,t1) = ml.latest();
        let v=prefix_proof_positions(7, 13);
        let proofs=ml.proofs(v.into_iter());
        assert!(verify_tree(&(s0,t0),&proofs));
        assert!(verify_tree(&(s1,t1),&proofs));
     }

}
