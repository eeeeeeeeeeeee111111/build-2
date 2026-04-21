#![no_main]
#![no_std]
#![feature(sync_unsafe_cell)]
#![allow(static_mut_refs)]

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use core::{ptr, slice};

use anyhow::{anyhow, Context, Error};
use hook::{Function, StaticHook, TrampolineHook};
use image_info::ImageInfo;
use obfstr::obfstr;
use pelite::{PeFile, PeView, Wrap};
use signature::Signature;

// ส่วน UEFI ที่ต้องใช้ (รวมกุญแจที่หายไป 15 จุด)
use uefi::{
    prelude::*,
    proto::{
        console::text::Color,
        device_path::{
            build::{self, DevicePathBuilder},
            text::{AllowShortcuts, DisplayOnly},
            DevicePath,
        },
        media::{
            file::{File, FileAttribute, FileMode},
            fs::SimpleFileSystem,
        },
    },
    table::boot::{LoadImageSource, OpenProtocolAttributes, OpenProtocolParams, SearchType},
    CStr16, Handle, Status, Identify
};

use uefi_core::system_table;
use utils::include_bytes_align_as;
use wdef::{
    ImgArchStartBootApplication, KLDR_DATA_TABLE_ENTRY, LoaderParameterBlock, OslFwpKernelSetupPhase1,
};

use crate::{
    uefi_core::{enter_execution_context, ExecutionContext},
    utils::{press_enter_to_continue, set_exit_boot_services, show_select},
};

extern crate alloc;
const WINDOWS_BOOTMGR_PATH: &'static [u16] =
    obfstr::wide!("\\efi\\microsoft\\boot\\bootmgfw.efi\0");

type FnExitBootServices =
    unsafe extern "efiapi" fn(image_handle: uefi_raw::Handle, map_key: usize) -> Status;

#[repr(align(16384))]
struct Align16384;

static TARGET_DRIVER: &'static [u8] =
    include_bytes_align_as!(Align16384, "driver/disks.sys");

pub struct ImageBuffer {
    pub address: *mut u8,
    pub size: usize,
}

impl ImageBuffer {
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.address, self.size) }
    }
}

static mut IMAGE_BUFFER: Option<ImageBuffer> = None;

type StaticTrampolineHook<H> = StaticHook<H, TrampolineHook<H>>;

pub static mut HOOK_IMG_ARCH_START_BOOT_APPLICATION: StaticTrampolineHook<
    ImgArchStartBootApplication,
> = StaticHook::new();
pub static mut HOOK_OSL_FWP_KERNEL_SETUP_PHASE1: StaticTrampolineHook<OslFwpKernelSetupPhase1> =
    StaticHook::new();

static mut ORIGINAL_EXIT_BOOT_SERVICES: Option<FnExitBootServices> = None;

static mut WINLOAD_IMAGE: Option<ImageInfo> = None;
static mut MAPPING_RESULT: Option<anyhow::Result<()>> = None;

mod hook;
mod image_info;
mod signature;
mod uefi_core;
mod utils;
mod wdef;
mod winload;

/* Called from the boot manager */
extern "efiapi" fn hooked_img_arch_start_boot_application(
    app_entry: *const (),
    image_base: *mut u8,
    image_size: u32,
    boot_option: u8,
    return_arguments: *mut (),
) -> u32 {
    let _exec_guard = enter_execution_context(ExecutionContext::WINBOOTMGR);

    log::debug!("[BOOTMGR] ImgArchStartBootApplication ถูกเรียก → กำลังตั้งค่า hook ใน winload.exe");

    let original = unsafe {
        HOOK_IMG_ARCH_START_BOOT_APPLICATION.disable();
        HOOK_IMG_ARCH_START_BOOT_APPLICATION
            .target()
            .unwrap_unchecked()
    };

    let winload = ImageInfo {
        image_base,
        image_size: image_size as usize,
    };

    if let Err(err) = setup_hooks_winload(winload) {
        log::error!("setup_hooks_winload ล้มเหลว: {:#}", err);
        utils::press_enter_to_continue();
    }

    log::debug!("[BOOTMGR] กำลังเรียก original ImgArchStartBootApplication");
    let result = original(
        app_entry,
        image_base,
        image_size,
        boot_option,
        return_arguments,
    );

    log::debug!("[BOOTMGR] ImgArchStartBootApplication กลับมาแล้ว (recovery mode?)");
    result
}

/* Called in WinLoad context */
extern "efiapi" fn hooked_osl_fwp_kernel_setup_phase1(lpb: *mut LoaderParameterBlock) -> u32 {
    let _exec_guard = enter_execution_context(ExecutionContext::WINLOAD);

    log::debug!("[WINLOAD] OslFwpKernelSetupPhase1 ถูกเรียก → กำลัง hijack driver");

    let original = unsafe {
        HOOK_OSL_FWP_KERNEL_SETUP_PHASE1.disable();
        HOOK_OSL_FWP_KERNEL_SETUP_PHASE1.target().unwrap_unchecked()
    };

    unsafe {
        MAPPING_RESULT = Some(handle_osl_lpb(lpb));
    }

    original(lpb)
}

unsafe extern "efiapi" fn hooked_exit_boot_services(
    image_handle: uefi_raw::Handle,
    map_key: usize,
) -> Status {
    let _exec_guard = enter_execution_context(ExecutionContext::UEFI);
    let original_fn = ORIGINAL_EXIT_BOOT_SERVICES.take().expect(obfstr!(
        "the original ExitBootServices callback to be saved"
    ));
    set_exit_boot_services(original_fn);

    fn finish_setup() -> anyhow::Result<()> {
        if unsafe { WINLOAD_IMAGE.is_none() } {
            anyhow::bail!(
                "{} has never been called.",
                obfstr!("ImgArchStartBootApplication")
            );
        }

        unsafe { MAPPING_RESULT.take() }
            .ok_or_else(|| anyhow!("{}", obfstr!("Mapping callback has never been called")))??;

        log::info!("[EXIT] ExitBootServices ถูกเรียกแล้ว");
        log::info!("[EXIT] Valthrun driver ถูก inject โดยการ hijack .sys driver (ไม่ allocate memory ใหม่เลย)");
        Ok(())
    }

    if let Err(err) = finish_setup() {
        log::error!("Failed to map the Valthrun driver!");
        log::error!("{:#}", err);
        press_enter_to_continue();
    } else {
        log::info!("{}", obfstr!("Valthrun driver successfully mapped (no allocation)."));
        press_enter_to_continue();
        log::info!("Booting Windows...");
    }

    winload::finalize();

    (original_fn)(image_handle, map_key)
}

fn initialize_output() -> uefi::Result<()> {
    let mut system_table = system_table();
    let stdout = system_table.stdout();

    let output_mode = stdout.modes().reduce(|acc, val| {
        if val.columns() * val.rows() < acc.columns() * acc.rows() {
            acc
        } else {
            val
        }
    });

    if let Some(output_mode) = output_mode {
        stdout.set_mode(output_mode)?;
    }

    stdout.set_color(Color::White, Color::Blue)?;
    stdout.clear()?;

    Ok(())
}

#[entry]
fn main(handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    let _exec_guard = enter_execution_context(ExecutionContext::UEFI);
    uefi_core::initialize(&system_table);
    unsafe {
    IMAGE_BUFFER = Some(ImageBuffer {
        address: TARGET_DRIVER.as_ptr() as *mut u8,
        size: TARGET_DRIVER.len(),
    });
}

    if let Err(err) = real_main(handle, &mut system_table) {
        log::error!("{}", obfstr!("Valthrun bootstrap error"));
        log::error!("{:#}", err);
        press_enter_to_continue();

        Status::LOAD_ERROR
    } else {
        Status::SUCCESS
    }
}

fn real_main(handle: Handle, system_table: &mut SystemTable<Boot>) -> anyhow::Result<()> {
    initialize_output()
        .map_err(|err| anyhow!("{}: {:#?}", obfstr!("Failed to initialize output"), err))?;

    let bs = system_table.boot_services();
    let windows_bootmgr = find_windows_bootmgr(handle, bs)?
        .with_context(|| obfstr!("Could not find Windows boot manager").to_string())?;

    log::debug!(
        "{} {}",
        obfstr!("Windows boot manager located at"),
        windows_bootmgr
            .to_string(bs, DisplayOnly(true), AllowShortcuts(false))
            .map_err(|err| anyhow!("{:#}", err))?
            .ok_or_else(|| anyhow!("{}", obfstr!("expected the path to be non empty")))?
    );

    let bootmgr_handle = bs
        .load_image(
            handle,
            LoadImageSource::FromDevicePath {
                device_path: &windows_bootmgr,
                from_boot_manager: true,
            },
        )
        .map_err(|err| anyhow!("{}: {}", obfstr!("failed to load Windows boot manager"), err))?;

    let bootmgr_image = ImageInfo::from_handle(bootmgr_handle.clone())?;
    setup_hooks_bootmgr(bootmgr_image)?;

    log::info!("Invoking bootmgr...");
    if let Err(err) = bs.start_image(bootmgr_handle) {
        if let Err(err) = bs.unload_image(bootmgr_handle) {
            log::warn!("{}: {:#}", obfstr!("Failed to unload Windows bootmgr image"), err);
        }
        anyhow::bail!(
            "{}: {}",
            obfstr!("failed to invoke Windows boot manager"),
            err
        )
    }

    log::error!("{}", obfstr!("The Windows boot manager exited unexpectedly."));
    Ok(())
}

fn find_windows_bootmgr(
    image_handle: Handle,
    boot_services: &BootServices,
) -> anyhow::Result<Option<Box<DevicePath>>> {
    // ... (โค้ดเดิมไม่เปลี่ยน) ...
    // (เพื่อความกระชับ ฉันคงส่วนนี้ไว้เหมือนเดิม)
    let file_systems = boot_services
        .locate_handle_buffer(SearchType::ByProtocol(&SimpleFileSystem::GUID))
        .map_err(|err| anyhow!("{}: {:#}", obfstr!("locating simple fs"), err))?;

    let mut found_devices = Vec::new();
    let windows_bootmgr_path = CStr16::from_u16_with_nul(WINDOWS_BOOTMGR_PATH).unwrap();

    for handle in file_systems.iter() {
        let device_path = boot_services
            .open_protocol_exclusive::<DevicePath>(*handle)
            .map_err(|err| anyhow!("{}: {:#}", obfstr!("open device path"), err))?;

        let file_system = unsafe {
            boot_services.open_protocol::<SimpleFileSystem>(
                OpenProtocolParams {
                    handle: handle.clone(),
                    agent: image_handle,
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        };
        let file_system = match file_system {
            Ok(fs) => fs,
            Err(err) => {
                log::warn!(
                    "{} 0x{:X}: {}",
                    obfstr!("Failed to open simple fs handle"),
                    handle.as_ptr() as u64,
                    err
                );
                continue;
            }
        };
        let file_system = file_system.get_mut().expect("the file system to be present");

        let mut volume = match file_system.open_volume() {
            Ok(volume) => volume,
            Err(err) => {
                log::warn!(
                    "{} 0x{:X}: {:#?}",
                    obfstr!("Failed to open volume for simple fs handle"),
                    handle.as_ptr() as u64,
                    err
                );
                continue;
            }
        };

        if volume
            .open(
                &windows_bootmgr_path,
                uefi::proto::media::file::FileMode::Read,
                uefi::proto::media::file::FileAttribute::READ_ONLY,
            )
            .is_ok()
        {
            let device_path_raw: &[u8] = device_path.as_bytes();
            let device_name =
                get_device_name_from_variable(device_path_raw).unwrap_or_else(|| "unknown".to_string());
            found_devices.push((device_path, device_name));
        }
    }

    if !found_devices.is_empty() {
        let device_index = if found_devices.len() == 1 {
            0
        } else {
            show_select(found_devices.iter().map(|(_, name)| name.clone()).collect())
        };
        let device_path = &found_devices[device_index].0;
        let device_path = device_path
            .get()
            .expect("device path to be present")
            .to_boxed();

        let mut buffer = Vec::new();
        let file_device_path = device_path.node_iter().fold(
            build::DevicePathBuilder::with_vec(&mut buffer),
            |acc, entry| acc.push(&entry).unwrap(),
        );

        let file_device_path = file_device_path
            .push(&build::media::FilePath {
                path_name: &windows_bootmgr_path,
            })
            .unwrap()
            .finalize()
            .unwrap();

        return Ok(Some(file_device_path.to_boxed()));
    }

    Ok(None)
}

fn get_device_name_from_variable(device_path_raw: &[u8]) -> Option<String> {
    // ... (โค้ดเดิมไม่เปลี่ยน) ...
    // (เพื่อความกระชับ ฉันคงส่วนนี้ไว้เหมือนเดิม)
    let variable_keys = system_table()
        .runtime_services()
        .variable_keys()
        .map_err(|e| log::warn!("{}: {:?}", obfstr!("Failed to get variable keys"), e))
        .ok()?;

    variable_keys.iter().find_map(|variable_key| {
        let cstr_name = variable_key.name().ok().filter(|cstr| {
            cstr.to_string().starts_with(obfstr!("Boot"))
                && cstr.to_string().len() == 8
                && variable_key.vendor == uefi_raw::table::runtime::VariableVendor::GLOBAL_VARIABLE
        })?;

        let (data, _) = system_table()
            .runtime_services()
            .get_variable_boxed(&cstr_name, &variable_key.vendor)
            .ok()?;

        let description_start = 6;
        let file_path_list_length = {
            let len = u16::from_le_bytes([data[4], data[5]]) as usize;
            (len != 0).then_some(len)?
        };

        let description = String::from_utf16(
            &data[description_start..]
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .take_while(|&u| u != 0)
                .collect::<Vec<u16>>(),
        )
        .ok()?;

        let file_path_list_start = description_start + (description.len() * 2) + 2;

        data.len().checked_sub(file_path_list_start).and_then(|_| {
            let file_path_list =
                &data[file_path_list_start..file_path_list_start + file_path_list_length];

            let mut nodes = Vec::new();
            let mut start = 0;
            let node_entire_end: [u8; 4] = [0x7f, 0xff, 0x04, 0x00];

            for i in 0..(file_path_list.len() - 4 + 1) {
                if &file_path_list[i..i + 4] == &node_entire_end {
                    if start < i {
                        nodes.push(&file_path_list[start..i]);
                    }
                    start = i + 4;
                }
            }

            nodes.iter().find_map(|node| {
                device_path_raw
                    .starts_with(node)
                    .then(|| description.clone())
            })
        })
    })
}

fn setup_hooks_bootmgr(image: ImageInfo) -> anyhow::Result<()> {
    let func_address = image.resolve_signature(&Signature::pattern("ImgArchStartBootApplication", "48 8B C4 48 89 58 ? 44 89 40 ? 48 89 50 ? 48 89 48 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 68 ? 48 81 EC C0 00 00 00"))?;

    unsafe {
        HOOK_IMG_ARCH_START_BOOT_APPLICATION
            .initialize_trampoline(ImgArchStartBootApplication::from_ptr_usize(func_address));
        HOOK_IMG_ARCH_START_BOOT_APPLICATION.enable(hooked_img_arch_start_boot_application);
    }

    log::debug!("[BOOTMGR] Hook ImgArchStartBootApplication ตั้งค่าเรียบร้อยแล้ว");
    Ok(())
}

fn setup_hooks_winload(image: ImageInfo) -> anyhow::Result<()> {
    winload::initialize(&image)?;

    let osl_fwp_kernel_setup_phase1 = image.resolve_signature(&Signature::pattern(
        obfstr!("OslFwpKernelSetupPhase1"),
        obfstr!("48 89 4C 24 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D"),
    ))?;

    unsafe {
        WINLOAD_IMAGE = Some(image);

        HOOK_OSL_FWP_KERNEL_SETUP_PHASE1.initialize_trampoline(
            OslFwpKernelSetupPhase1::from_ptr_usize(osl_fwp_kernel_setup_phase1),
        );
        HOOK_OSL_FWP_KERNEL_SETUP_PHASE1.enable(hooked_osl_fwp_kernel_setup_phase1);

        ORIGINAL_EXIT_BOOT_SERVICES = Some(set_exit_boot_services(hooked_exit_boot_services));
    }

    log::debug!("[WINLOAD] Hook OslFwpKernelSetupPhase1 + ExitBootServices ตั้งค่าเรียบร้อย (ไม่มี BlImgAllocateImageBuffer แล้ว)");
    Ok(())
}

trait LoaderParameterBlockEx {
    fn find_module(&self, name: &str) -> anyhow::Result<Option<&KLDR_DATA_TABLE_ENTRY>>;
}

impl LoaderParameterBlockEx for LoaderParameterBlock {
    fn find_module(&self, name: &str) -> anyhow::Result<Option<&KLDR_DATA_TABLE_ENTRY>> {
        // ... (โค้ดเดิมไม่เปลี่ยน) ...
        let mut current_entry = self.LoadOrderListHead.Flink;
        while current_entry as *const _ != &self.LoadOrderListHead {
            let entry = unsafe {
                current_entry
                    .cast::<KLDR_DATA_TABLE_ENTRY>()
                    .as_ref()
                    .with_context(|| obfstr!("flink not to be null").to_string())?
            };
            current_entry = unsafe { current_entry.as_ref() }
                .with_context(|| obfstr!("flink not to be null").to_string())?
                .Flink;

            let base_image_name = unsafe {
                slice::from_raw_parts(
                    entry.BaseImageName.Buffer,
                    (entry.BaseImageName.Length / 2) as usize,
                )
            };

            let image_name = String::from_utf16_lossy(base_image_name);
            if image_name == name {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }
}

fn handle_osl_lpb(lpb: *mut LoaderParameterBlock) -> anyhow::Result<()> {
    log::debug!("[WINLOAD] handle_osl_lpb ถูกเรียก (LPB = {:X})", lpb as u64);

    let lpb = unsafe { &*lpb };

    // ==================== คำนวณขนาด driver ที่ต้องการก่อน ====================
    let pe = PeFile::from_bytes(TARGET_DRIVER)
        .map_err(|e| anyhow!("Parse TARGET_DRIVER ล้มเหลว: {}", e))?;
    let custom_size = match pe.optional_header() {
        Wrap::T32(h) => h.SizeOfImage,
        Wrap::T64(h) => h.SizeOfImage,
    } as usize;

    log::info!("[WINLOAD] Custom driver size = {:X} bytes", custom_size);

    // ==================== สแกน dynamic + ปลอดภัย + เช็คขนาดพอ ====================
    let mut candidates: Vec<(&KLDR_DATA_TABLE_ENTRY, String)> = Vec::new();
    let mut current_entry = lpb.LoadOrderListHead.Flink;

    while current_entry as *const _ != &lpb.LoadOrderListHead {
        let entry = unsafe {
            current_entry
                .cast::<KLDR_DATA_TABLE_ENTRY>()
                .as_ref()
                .with_context(|| obfstr!("flink not to be null").to_string())?
        };
        current_entry = unsafe { current_entry.as_ref() }
            .with_context(|| obfstr!("flink not to be null").to_string())?
            .Flink;

        let base_image_name = unsafe {
            slice::from_raw_parts(
                entry.BaseImageName.Buffer,
                (entry.BaseImageName.Length / 2) as usize,
            )
        };

        let image_name = String::from_utf16_lossy(base_image_name).to_lowercase();

        if image_name.ends_with(".sys")
            && entry.ImageBase != ptr::null_mut()
            && entry.SizeOfImage as usize >= custom_size
        {
            candidates.push((entry, image_name));
        }
    }

    if candidates.is_empty() {
        return Err(anyhow::anyhow!(
            "ไม่พบ .sys ตัวไหนที่ใหญ่พอสำหรับ hijack (ต้องการอย่างน้อย {:X} bytes)",
            custom_size
        ));
    }

    candidates.sort_by(|a, b| b.0.SizeOfImage.cmp(&a.0.SizeOfImage));
    let (hijacked_driver, hijacked_name) = &candidates[0];

    log::info!(
        "[WINLOAD] เลือก hijack driver: {} (Size: {:X} → พอสำหรับ custom {:X})",
        hijacked_name,
        hijacked_driver.SizeOfImage,
        custom_size
    );

    if candidates.len() > 1 {
        let others: Vec<&str> = candidates.iter().skip(1).map(|(_, n)| n.as_str()).collect();
        log::debug!("[WINLOAD] อื่น ๆ ที่พบ: {:?}", others);
    }

    // ==================== เตรียมข้อมูลก่อน overwrite ====================
    let hijacked_image_base = hijacked_driver.ImageBase;
    let hijacked_size = hijacked_driver.SizeOfImage as usize;
    let hijacked_driver_memory =
        unsafe { slice::from_raw_parts_mut(hijacked_image_base as *mut u8, hijacked_size) };

    let rva_hijacked_entry_point = {
        let hijacked_pe = PeView::from_bytes(hijacked_driver_memory)
            .map_err(Error::msg)
            .context("parse hijacked driver")?;

        match hijacked_pe.optional_header() {
            Wrap::T32(header) => header.AddressOfEntryPoint,
            Wrap::T64(header) => header.AddressOfEntryPoint,
        }
    } as usize;

    const DRIVER_ENTRYPOINT_BUFFER_SIZE: usize = 0x20;
    let original_entry_bytes = {
        let start = rva_hijacked_entry_point;
        let end = start + DRIVER_ENTRYPOINT_BUFFER_SIZE;
        if end > hijacked_size {
            anyhow::bail!("Entry point ของ hijacked driver อยู่นอกขอบเขต memory");
        }
        hijacked_driver_memory[start..end].to_vec()
    };

    log::debug!(
        "[WINLOAD] Hijacked base = {:X}, entry point RVA = {:X}, original bytes saved",
        hijacked_image_base as u64,
        rva_hijacked_entry_point
    );

    // ==================== Map โดยตรง (ไม่ allocate) ====================
    map_custom_driver(
        hijacked_driver_memory,
        &TARGET_DRIVER,
        &original_entry_bytes,
        rva_hijacked_entry_point,
        hijacked_image_base as u64,
    )
    .context("mapping error")?;

    log::info!("[WINLOAD] Map driver เสร็จสิ้นโดยไม่ allocate memory ใหม่");
    Ok(())
}

/*
 * Map the specially crafted driver โดยตรงเข้า memory ของ hijacked .sys
 * ไม่มีการ allocate ใหม่เลย 100%
 */
fn map_custom_driver(
    hijacked_memory: &mut [u8],
    target_driver_file: &[u8],
    original_hijacked_entry_bytes: &[u8],
    rva_hijacked_entry_point: usize,
    base_address: u64,
) -> anyhow::Result<()> {
    log::debug!("[MAP] กำลัง overwrite memory ของ hijacked driver (base {:X})", base_address);

    hijacked_memory.fill(0x00);

    let pe = PeFile::from_bytes(target_driver_file).map_err(Error::msg)?;

    log::debug!("Mapping {} sections", pe.section_headers().as_slice().len());
    for section in pe.section_headers() {
        let section_name = String::from_utf8_lossy(section.name_bytes()).to_string();
        let should_map = true; // .text .data และอื่น ๆ ทุก section

        if !should_map {
            log::debug!(" Skipping {}", section_name);
            continue;
        }

        let va = section.VirtualAddress as usize;
        let raw_size = section.SizeOfRawData as usize;

        if va + raw_size > hijacked_memory.len() {
            anyhow::bail!(
                "section {} ใหญ่เกิน memory ที่มี (va: {:X}, size: {:X}, mem: {:X})",
                section_name,
                va,
                raw_size,
                hijacked_memory.len()
            );
        }

        let section_memory = &mut hijacked_memory[va..va + raw_size];
        let section_data = &target_driver_file
            [section.PointerToRawData as usize..section.PointerToRawData as usize + raw_size];
        section_memory.copy_from_slice(section_data);

        log::debug!(" Mapped section {}", section_name);
    }

    /* Relocations */
    let relocs = pe.base_relocs().map_err(Error::msg)?;
    for reloc_block in relocs.iter_blocks() {
        for reloc in reloc_block.words() {
            match reloc_block.type_of(reloc) {
                0x00 => continue,
                0x0A => {
                    let rva = reloc_block.rva_of(reloc) as usize;
                    let value = u64::from_le_bytes(hijacked_memory[rva..rva + 8].try_into().unwrap());
                    let image_base = match pe.optional_header() {
                        Wrap::T32(header) => header.ImageBase as u64,
                        Wrap::T64(header) => header.ImageBase as u64,
                    };

                    if value < image_base {
                        continue;
                    }

                    let new_address = base_address + value - image_base;
                    hijacked_memory[rva..rva + 8].copy_from_slice(&new_address.to_le_bytes());
                }
                reloc_type => anyhow::bail!("Unsupported reloc type {:X}", reloc_type),
            }
        }
    }

    /* Hijack entry point */
    let rva_driver_entry_point = match pe.optional_header() {
        Wrap::T32(header) => header.AddressOfEntryPoint,
        Wrap::T64(header) => header.AddressOfEntryPoint,
    } as usize;

    let exports = pe.exports().map_err(Error::msg)?.by().map_err(Error::msg)?;
    let rva_original_entry_bytes = exports
        .name_linear("_ENTRY_BYTES")
        .ok()
        .context("Could not find _ENTRY_BYTES export")?
        .symbol()
        .context("Expected _ENTRY_BYTES to be a symbol")?
        as usize;

    hijacked_memory[rva_original_entry_bytes
        ..rva_original_entry_bytes + original_hijacked_entry_bytes.len()]
        .copy_from_slice(original_hijacked_entry_bytes);

    let mut instructions = Vec::<u8>::with_capacity(0x20);
    instructions.extend(&[0x4C, 0x8D, 0x05, 0xF9, 0xFF, 0xFF, 0xFF]); // lea r8, [rip-7]
    instructions.extend(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]); // jmp [rip+0]
    instructions.extend(&(base_address + rva_driver_entry_point as u64).to_le_bytes());

    hijacked_memory[rva_hijacked_entry_point..rva_hijacked_entry_point + instructions.len()]
        .copy_from_slice(&instructions);

    log::debug!(
        "[MAP] Hijack สำเร็จ → entry point เดิมถูกบันทึกไว้ที่ RVA {:X} ใน custom driver",
        rva_original_entry_bytes
    );

    Ok(())
}