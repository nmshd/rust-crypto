use crate::common::traits::log_config::LogConfig;
#[derive(Debug)]
pub struct SecureEnclaveLogger; 

impl LogConfig for SecureEnclaveLogger{
    fn setup_logging(&self){
        println!("Logger muss noch erstellt und implementiert werden!"); 
    }
}