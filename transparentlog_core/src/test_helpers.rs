use crate::{TransparentLog, proof_positions, verify, prefix_proof_positions, verify_tree, hash, check_record, LogClient, Record, LogTree};
use std::fmt::{Display,Formatter, Result};
use crypto::{sha2::Sha256, digest::Digest};
use num::{Zero,One};
use std::fmt::Debug;
use serde::{Serialize,Deserialize};
use core::ops::Deref;
 
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