// Stub skeleton when BPF build fails
use std::os::unix::io::AsRawFd;

pub struct GoodbyedpiSkelBuilder;

impl Default for GoodbyedpiSkelBuilder {
    fn default() -> Self {
        Self
    }
}

impl GoodbyedpiSkelBuilder {
    pub fn obj_builder(&mut self, _debug: bool) -> &mut Self {
        self
    }
    
    pub fn open(&self) -> anyhow::Result<OpenGoodbyedpiSkel> {
        anyhow::bail!("BPF skeleton not available - build eBPF first")
    }
}

pub struct OpenGoodbyedpiSkel;

impl OpenGoodbyedpiSkel {
    pub fn maps(&self) -> Maps {
        Maps
    }
    
    pub fn progs(&self) -> Progs {
        Progs
    }
    
    pub fn progs_mut(&mut self) -> ProgsMut {
        ProgsMut
    }
    
    pub fn load(self) -> anyhow::Result<GoodbyedpiSkel> {
        anyhow::bail!("BPF skeleton not available - build eBPF first")
    }
}

pub struct GoodbyedpiSkel;

pub struct Maps;

impl Maps {
    pub fn config_map(&self) -> ConfigMap {
        ConfigMap
    }
    
    pub fn events(&self) -> Events {
        Events
    }
}

pub struct ConfigMap;
pub struct Events;

impl libbpf_rs::MapCore for ConfigMap {
    fn fd(&self) -> i32 { -1 }
    fn set_value_size(&self, _size: u32) -> libbpf_rs::Result<()> { Ok(()) }
    fn key_size(&self) -> u32 { 4 }
    fn value_size(&self) -> u32 { 16 }
    fn lookup(&self, _key: &[u8], _flags: libbpf_rs::MapFlags) -> libbpf_rs::Result<Option<Vec<u8>>> { Ok(None) }
    fn lookup_and_delete(&self, _key: &[u8]) -> libbpf_rs::Result<Option<Vec<u8>>> { Ok(None) }
    fn update(&self, _key: &[u8], _value: &[u8], _flags: libbpf_rs::MapFlags) -> libbpf_rs::Result<()> { Ok(()) }
    fn delete(&self, _key: &[u8]) -> libbpf_rs::Result<()> { Ok(()) }
    fn lookup_batch(&self, _batch_size: u32, _keys: &mut [&mut [u8]], _values: &mut [&mut [u8]], _opts: Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>) -> libbpf_rs::Result<(u32, Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>)> { Ok((0, None)) }
    fn lookup_and_delete_batch(&self, _batch_size: u32, _keys: Option<&mut [&mut [u8]]>, _values: &mut [&mut [u8]], _opts: Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>) -> libbpf_rs::Result<(u32, Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>)> { Ok((0, None)) }
    fn update_batch(&self, _keys: &[&[u8]], _values: &[&[u8]], _opts: Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>) -> libbpf_rs::Result<Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>> { Ok(None) }
    fn delete_batch(&self, _keys: &[&[u8]], _opts: Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>) -> libbpf_rs::Result<Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>> { Ok(None) }
}

impl libbpf_rs::MapCore for Events {
    fn fd(&self) -> i32 { -1 }
    fn set_value_size(&self, _size: u32) -> libbpf_rs::Result<()> { Ok(()) }
    fn key_size(&self) -> u32 { 0 }
    fn value_size(&self) -> u32 { 256 }
    fn lookup(&self, _key: &[u8], _flags: libbpf_rs::MapFlags) -> libbpf_rs::Result<Option<Vec<u8>>> { Ok(None) }
    fn lookup_and_delete(&self, _key: &[u8]) -> libbpf_rs::Result<Option<Vec<u8>>> { Ok(None) }
    fn update(&self, _key: &[u8], _value: &[u8], _flags: libbpf_rs::MapFlags) -> libbpf_rs::Result<()> { Ok(()) }
    fn delete(&self, _key: &[u8]) -> libbpf_rs::Result<()> { Ok(()) }
    fn lookup_batch(&self, _batch_size: u32, _keys: &mut [&mut [u8]], _values: &mut [&mut [u8]], _opts: Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>) -> libbpf_rs::Result<(u32, Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>)> { Ok((0, None)) }
    fn lookup_and_delete_batch(&self, _batch_size: u32, _keys: Option<&mut [&mut [u8]]>, _values: &mut [&mut [u8]], _opts: Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>) -> libbpf_rs::Result<(u32, Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>)> { Ok((0, None)) }
    fn update_batch(&self, _keys: &[&[u8]], _values: &[&[u8]], _opts: Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>) -> libbpf_rs::Result<Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>> { Ok(None) }
    fn delete_batch(&self, _keys: &[&[u8]], _opts: Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>) -> libbpf_rs::Result<Option<libbpf_rs::libbpf_sys::bpf_map_batch_opts>> { Ok(None) }
}

pub struct Progs;
pub struct ProgsMut;

impl ProgsMut {
    pub fn dpi_egress(&mut self) -> ProgramMut {
        ProgramMut
    }
    
    pub fn dpi_ingress(&mut self) -> ProgramMut {
        ProgramMut
    }
}

pub struct ProgramMut;

impl AsRawFd for ProgramMut {
    fn as_raw_fd(&self) -> i32 {
        -1
    }
}
