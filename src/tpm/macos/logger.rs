use tracing_subscriber::{layer::SubscriberExt, Registry}; 
use crate::common::traits::log_config::LogConfig;
#[derive(Debug)]
pub struct SwiftLogger; 

impl LogConfig for SwiftLogger{
    fn setup_logging(&self){
        todo!(); 
    }
}