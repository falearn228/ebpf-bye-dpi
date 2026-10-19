//! Библиотечная часть демона. Её же использует CLI (`goodbyedpi doctor`,
//! `validate`, `tui`), чтобы проверять профили и eBPF-объект тем же кодом,
//! которым их загружает демон.

pub mod auto_logic;
pub mod bpf;
pub mod config;
pub mod control;
pub mod injector;
pub mod l7;
pub mod metrics;
pub mod profile;
pub mod ringbuf;
pub mod rules;
pub mod state;
pub mod tc;
