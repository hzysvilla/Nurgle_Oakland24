mod reward;

extern crate byteorder;
extern crate console;
extern crate fs2;
extern crate hex;
extern crate itertools;
extern crate ocl;
extern crate ocl_extras;
extern crate rand;
extern crate rayon;
extern crate separator;
extern crate terminal_size;
extern crate tiny_keccak;
use std::ops::Add;
use std::error::Error;
use std::i64;
use std::io::prelude::*;
use std::fs::OpenOptions;
use std::time::{SystemTime, UNIX_EPOCH};

use byteorder::{ByteOrder, BigEndian, LittleEndian};
use console::Term;
use fs2::FileExt;
use hex::FromHex;
use itertools::Itertools;
use ocl::{ProQue, Buffer, MemFlags, Platform, Device, Context, Queue, Program};
use rand::{thread_rng, Rng};
use rayon::prelude::*;
use separator::Separatable;
use terminal_size::{Width, Height, terminal_size};
use tiny_keccak::Keccak;

const WORK_SIZE: u32 = 0x8000000; // max. 0x15400000 to abs. max 0xffffffff

const WORK_FACTOR: u128 = (WORK_SIZE as u128) / 1_000_000;
const ZERO_BYTE: u8 = 0x00;
const EIGHT_ZERO_BYTES: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
const CONTROL_CHARACTER: u8 = 0xff;
const ZERO_REWARD: &str = "0";
const MAX_INCREMENTER: u64 = 0xffffffffffff;

static KERNEL_SRC: &'static str = include_str!("./kernels/keccak256.cl");

pub struct Config {
    pub gpu_device: u8,
    pub leading_zeroes_threshold: u8,
    pub prefix: [u8;32],
}

impl Config {
    pub fn new(mut args: std::env::Args) -> Result<Self, &'static str> {
        args.next();

      
        let gpu_device_string = match args.next() {
            Some(arg) => arg,
            None => String::from("255"),
        };

        let leading_zeroes_threshold_string= match args.next() {
            Some(arg) => arg,
            None => String::from("3"),
        };

        let mut prefix_string=match args.next(){
            Some(arg) => arg,
            None => return Err ("didn't get a prefix!"),
        };

        let gpu_device: u8 = match gpu_device_string
                                               .parse::<u8>() {
            Ok(t) => t,
            Err(_) => {
                return Err(
                    "invalid gpu device value."
                )
            }
        };

        let leading_zeroes_threshold = match leading_zeroes_threshold_string
                                               .parse::<u8>() {
            Ok(t) => t,
            Err(_) => {
                return Err(
                    "invalid leading zeroes threshold value supplied."
                )
            }
        };

        if leading_zeroes_threshold > 20 {
            return Err("invalid value for leading zeroes threshold argument. (valid: 0 .. 20)")
        }
     if prefix_string.starts_with("0x") {
        prefix_string = without_prefix(prefix_string)
    }
      let prefix_vec: Vec<u8> = match Vec::from_hex(
        &prefix_string
    ) {
        Ok(t) => t,
        Err(_) => {
            return Err("could not decode prefix argument.")
        }
    };
    
    if prefix_vec.len() != 32 {
        return Err("invalid length for initialization code hash argument.")
    }
    let prefix=to_fixed_32(prefix_vec);
        Ok(
          Self {
            gpu_device,
            leading_zeroes_threshold,
            prefix
          }
        )
    }
}


pub fn gpu(config: Config) -> ocl::Result<()> {
    let file = OpenOptions::new()
                 .append(true)
                 .create(true)
                 .open("efficient_addresses.txt")
                 .expect(
                   "Could not create or open `efficient_addresses.txt` file."
                 );

    let rewards = reward::Reward::new();

    let mut found: u64 = 0;
    let mut found_list: Vec<String> = vec![];

    let term = Term::stdout();

    let platform = Platform::default();

    let device = Device::by_idx_wrap(platform, config.gpu_device as usize)?;

    let context = Context::builder()
                    .platform(platform)
                    .devices(device.clone())
                    .build()?;
    
    let pre:[u8;32]=config.prefix;

    let kernel_src = &format!(
        "{}\n#define LEADING_ZEROES {}\n{}",
        pre
        .iter()
        .enumerate()
        .map(|(i, x)| format!("#define S_{} {}u\n", i + 1, x))
        .collect::<String>(),
        config.leading_zeroes_threshold,
        KERNEL_SRC
    );

    let program = Program::builder()
                    .devices(device)
                    .src(kernel_src)
                    .build(&context)?;

    let queue = Queue::new(&context, device, None)?;

    let ocl_pq = ProQue::new(context, queue, program, Some(WORK_SIZE));

    let mut rng = thread_rng();

    let start_time: f64 = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as f64;

    let mut rate: f64 = 0.0;
    let mut cumulative_nonce: u64 = 0;

    let mut previous_time: f64 = 0.0;

    let mut work_duration_millis: u64 = 0;

    let mut n = num::BigInt::from(0);
    let mut zeronum= num::BigInt::from(0);

    loop {
        let (_, bytes) = n.to_bytes_be();
        let mut salt: Vec<u8> = Vec::new();
        let l = bytes.len();
        if l < 12 {
            salt.extend(vec![0u8; 12 - l].iter());
            salt.extend(bytes);
        } else {
            salt.extend(&bytes[(l - 12)..l]);
        }
  
        let message: [u8; 12] = to_fixed_12(&salt);

        let message_buffer = Buffer::builder()
                               .queue(ocl_pq.queue().clone())
                               .flags(MemFlags::new().read_only())
                               .len(12)
                               .copy_host_slice(&message)
                               .build()?;
        
        let mut nonce: [u32; 1] = [0];
        let mut view_buf = [0; 8];

        let mut nonce_buffer = Buffer::builder()
                                 .queue(ocl_pq.queue().clone())
                                 .flags(MemFlags::new().read_only())
                                 .len(1)
                                 .copy_host_slice(&nonce)
                                 .build()?;

        let mut solutions: Vec<u64> = vec![0; 1];
        let solutions_buffer: Buffer<u64> = Buffer::builder()
                                              .queue(ocl_pq.queue().clone())
                                              .flags(MemFlags::new().write_only())
                                              .len(1)
                                              .copy_host_slice(&solutions)
                                              .build()?;

        loop {
            let kern = ocl_pq.kernel_builder("hashMessage")
                         .arg_named("message", None::<&Buffer<u8>>)
                         .arg_named("nonce", None::<&Buffer<u32>>)
                         .arg_named("solutions", None::<&Buffer<u64>>)
                         .build()?;

            kern.set_arg("message", Some(&message_buffer))?;
            kern.set_arg("nonce", Some(&nonce_buffer))?;
            kern.set_arg("solutions", &solutions_buffer)?;

            unsafe { kern.enq()?; }

            let mut now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let current_time: f64 = now.as_secs() as f64;

            let print_output: bool = current_time - previous_time > 0.99;
            previous_time = current_time;

            cumulative_nonce += 1;

            solutions_buffer.read(&mut solutions).enq()?;

            if solutions[0] != 0 {
                break;
            }

            if nonce[0]==4294967295{
                break;
            }

            nonce[0] += 1;

            nonce_buffer = Buffer::builder()
                             .queue(ocl_pq.queue().clone())
                             .flags(MemFlags::new().read_write())
                             .len(1)
                             .copy_host_slice(&nonce)
                             .build()?;
        }
        
        solutions
          .iter()
          .filter(|&i| *i != 0)
          .map(|i| u64_to_le_fixed_8(i))
          .for_each(|solution| {
            if &solution != &EIGHT_ZERO_BYTES {
                let mut solution_message: Vec<u8> = vec![];

                solution_message.extend(salt.iter());
                solution_message.extend(solution.iter());

                let mut hash = Keccak::new_keccak256();

                hash.update(&solution_message);

                let mut res: [u8; 32] = [0; 32];
                hash.finalize(&mut res);

                let mut leading = 0;

                for (i, b) in res.iter().enumerate() {
                    if b != &ZERO_BYTE {
                        leading = i;
                        break;
                    }
                }

                let key = leading * 20;

                let mut address_hashret: [u8; 32] = Default::default();
                address_hashret.copy_from_slice(&res[0..]);

                let address_hashret_hex_string = hex::encode(& address_hashret);
                let address_hashret_str = format!("0x{}", &address_hashret_hex_string);

             
                let reward_amount = rewards.get(&key);

                let output = format!(
                  "0x{}{}",
                  hex::encode(&salt),
                  hex::encode(&solution),
                );

                let show = format!("{} ({})", &output, &leading);
                let next_found = vec![show.to_string()];
                found_list.extend(next_found);

                file.lock_exclusive().expect("Couldn't lock file.");

                writeln!(&file, "{}", &output).expect(
                  "Couldn't write to `efficient_addresses.txt` file."
                );

                file.unlock().expect("Couldn't unlock file.");
                found = found + 1;
                print!("{}\n", &output);
                let mut now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let current_time: f64 = now.as_secs() as f64;

                let total_runtime = current_time - start_time;
                let total_runtime_hrs = *&total_runtime as u64 / (3600);
                let total_runtime_mins = (
                    *&total_runtime as u64 - &total_runtime_hrs * 3600
                ) / 60;
                let total_runtime_secs = &total_runtime - (
                    &total_runtime_hrs * 3600
                ) as f64 - (&total_runtime_mins * 60) as f64;
            
                let total_runtime = current_time - start_time;
                let total_runtime_hrs = *&total_runtime as u64 / (3600);
                let total_runtime_mins = (
                    *&total_runtime as u64 - &total_runtime_hrs * 3600
                ) / 60;
                let total_runtime_secs = &total_runtime - (
                    &total_runtime_hrs * 3600
                ) as f64 - (&total_runtime_mins * 60) as f64;

                print!("total runtime: {}:{:02}:{:02}\n ",
                    total_runtime_hrs,
                    total_runtime_mins,
                    total_runtime_secs,
                ); 
                
                std::process::exit(2);
            }
        });
        n = n.add(1);
    }
}

fn without_prefix(string: String) -> String {
    string
      .char_indices()
      .nth(2)
      .and_then(|(i, _)| string.get(i..))
      .unwrap()
      .to_string()
}

fn to_fixed_20(bytes: std::vec::Vec<u8>) -> [u8; 20] {
    let mut array = [0; 20];
    let bytes = &bytes[..array.len()];
    array.copy_from_slice(bytes);
    array
}

fn to_fixed_32(bytes: std::vec::Vec<u8>) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()];
    array.copy_from_slice(bytes);
    array
}

fn to_fixed_47(bytes: &std::vec::Vec<u8>) -> [u8; 47] {
    let mut array = [0; 47];
    let bytes = &bytes[..array.len()];
    array.copy_from_slice(bytes);
    array
}

fn to_fixed_4(bytes: &std::vec::Vec<u8>) -> [u8; 4] {
    let mut array = [0; 4];
    let bytes = &bytes[..array.len()];
    array.copy_from_slice(bytes);
    array
}

fn to_fixed_12(bytes: &std::vec::Vec<u8>) -> [u8; 12] {
    let mut array = [0; 12];
    let bytes = &bytes[..array.len()];
    array.copy_from_slice(bytes);
    array
}

fn u64_to_fixed_6(x: &u64) -> [u8; 6] {
    let mask: u64 = 0xff;
    let b1: u8 = ((x >> 40) & mask) as u8;
    let b2: u8 = ((x >> 32) & mask) as u8;
    let b3: u8 = ((x >> 24) & mask) as u8;
    let b4: u8 = ((x >> 16) & mask) as u8;
    let b5: u8 = ((x >> 8) & mask) as u8;
    let b6: u8 = (x & mask) as u8;
    [b1, b2, b3, b4, b5, b6]
}

fn u64_to_le_fixed_8(x: &u64) -> [u8; 8] {
    let mask: u64 = 0xff;
    let b1: u8 = ((x >> 56) & mask) as u8;
    let b2: u8 = ((x >> 48) & mask) as u8;
    let b3: u8 = ((x >> 40) & mask) as u8;
    let b4: u8 = ((x >> 32) & mask) as u8;
    let b5: u8 = ((x >> 24) & mask) as u8;
    let b6: u8 = ((x >> 16) & mask) as u8;
    let b7: u8 = ((x >> 8) & mask) as u8;
    let b8: u8 = (x & mask) as u8;
    [b8, b7, b6, b5, b4, b3, b2, b1]
}
