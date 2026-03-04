use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../ebpf/src/goodbyedpi.bpf.c");
    println!("cargo:rerun-if-changed=../ebpf/src/Makefile");
    println!("cargo:rerun-if-changed=build.rs");

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let bpf_dir = PathBuf::from("../ebpf/src");
    let bpf_obj_src = bpf_dir.join("goodbyedpi.bpf.o");
    let bpf_obj_out = out.join("goodbyedpi.bpf.o");
    let skel_out = out.join("goodbyedpi.skel.rs");

    // Check if tools are available
    let make_check = Command::new("which").arg("make").output();
    let has_make = make_check.is_ok_and(|o| o.status.success());
    let bpftool_check = Command::new("which").arg("bpftool").output();
    let has_bpftool = bpftool_check.is_ok_and(|o| o.status.success());

    let src_file = bpf_dir.join("goodbyedpi.bpf.c");
    let mut obj_compiled = false;

    // Compile eBPF using Makefile if available
    if src_file.exists() && has_make {
        println!("cargo:warning=Compiling eBPF using Makefile...");

        let make_status = Command::new("make")
            .current_dir(&bpf_dir)
            .arg("goodbyedpi.bpf.o")
            .status();

        match make_status {
            Ok(s) if s.success() => {
                // Copy compiled object to OUT_DIR
                if bpf_obj_src.exists() {
                    match std::fs::copy(&bpf_obj_src, &bpf_obj_out) {
                        Ok(_) => {
                            println!(
                                "cargo:warning=eBPF object compiled and copied to: {}",
                                bpf_obj_out.display()
                            );
                            obj_compiled = true;
                        }
                        Err(e) => {
                            println!("cargo:warning=Failed to copy object file: {}", e);
                        }
                    }
                } else {
                    println!(
                        "cargo:warning=Compiled object not found at: {}",
                        bpf_obj_src.display()
                    );
                }
            }
            Ok(s) => {
                println!("cargo:warning=make failed with status: {:?}", s.code());
            }
            Err(e) => {
                println!("cargo:warning=Failed to run make: {}", e);
            }
        }
    } else if !has_make {
        println!("cargo:warning=make not found");
    } else if !src_file.exists() {
        println!(
            "cargo:warning=eBPF source not found: {}",
            src_file.display()
        );
    }

    // Generate skeleton if bpftool is available
    if obj_compiled && has_bpftool {
        println!("cargo:warning=Generating BPF skeleton with bpftool...");

        let skeleton = Command::new("bpftool")
            .args(["gen", "skeleton", bpf_obj_out.to_str().unwrap()])
            .output();

        match skeleton {
            Ok(out) if out.status.success() => {
                std::fs::write(&skel_out, out.stdout).expect("Failed to write skeleton");
                println!("cargo:warning=Successfully generated BPF skeleton");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                println!("cargo:warning=bpftool failed: {}, using stub", stderr);
                copy_stub(&skel_out);
            }
            Err(e) => {
                println!("cargo:warning=bpftool error: {}, using stub", e);
                copy_stub(&skel_out);
            }
        }
    } else {
        if !has_bpftool {
            println!("cargo:warning=bpftool not found, using stub skeleton");
        }
        copy_stub(&skel_out);
    }
}

fn copy_stub(skel_out: &PathBuf) {
    let stub = include_str!("stub.skel.rs");
    std::fs::write(skel_out, stub).expect("Failed to write stub skeleton");
}
