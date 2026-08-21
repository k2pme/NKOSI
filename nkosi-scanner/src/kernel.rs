use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelModule {
    pub name: String,
    pub size: u32,
    pub ref_count: u32,
    pub loaded_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelFinding {
    pub module: String,
    pub finding_type: String,
    pub severity: String,
    pub description: String,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelReport {
    pub timestamp: String,
    pub kernel_version: String,
    pub loaded_modules: Vec<KernelModule>,
    pub findings: Vec<KernelFinding>,
    pub score: u32,
    pub summary: String,
}

pub struct KernelScanner {
    whitelisted_modules: Vec<String>,
}

impl KernelScanner {
    pub fn new() -> Self {
        Self {
            whitelisted_modules: Self::get_whitelist(),
        }
    }

    fn get_whitelist() -> Vec<String> {
        vec![
            // Filesystems
            "ext4", "xfs", "btrfs", "vfat", "ntfs3", "fuse", "iso9660", "udf",
            // Network core
            "nf_conntrack", "nfnetlink", "nf_defrag_ipv4", "nf_defrag_ipv6",
            "iptable_filter", "ip6table_filter", "ip_tables", "ip6_tables",
            "x_tables", "nft_chain_nat", "nft_compat", "nft_masq", "nft_set",
            "nf_nat", "nf_tables", "xt_nat", "xt_tcpudp", "xt_conntrack",
            "xt_MASQUERADE", "xt_addrtype", "xt_set", "ip_set",
            // Bridge / bonding
            "bridge", "bonding", "8021q", "stp", "llc", "br_netfilter",
            // Sound
            "snd", "snd_hda_intel", "snd_soc", "snd_pcm", "snd_seq", "snd_timer",
            "snd_rawmidi", "soundcore", "ac97_bus", "soundwire_intel", "soundwire_cadence",
            "soundwire_bus", "soundwire_generic_allocation",
            // USB / HID
            "usbhid", "hid", "hid_generic", "hid_multitouch", "usb_storage", "uas",
            // GPU / Display
            "drm", "i915", "nouveau", "amdgpu", "xe", "gpu_sched", "ttm",
            // Storage
            "ahci", "libahci", "ata_piix", "sd_mod", "sr_mod", "nvme", "nvme_core",
            "nvme_auth", "rtsx_pci", "rtsx_pci_sdmmc", "mtd", "spi_nor",
            // Virtualization
            "kvm", "kvm_intel", "kvm_amd", "vhost_net", "tun", "tap", "veth",
            // Overlay / container
            "overlay", "veth",
            // Network drivers
            "iwlwifi", "iwlmvm", "cfg80211", "mac80211", "rfcomm", "btusb",
            "btrtl", "btbcm", "btintel", "btmtk", "bluetooth", "bnep",
            // Crypto
            "aesni_intel", "crypto_simd", "cryptd", "ccm", "cmac", "ghash_clmulni_intel",
            "crc32_pclmul", "sha256_ssse3", "sha1_ssse3", "polyval_clmulni", "polyval_generic",
            "ecdh_generic", "algif_hash", "algif_skcipher", "af_alg",
            // Compression
            "lz4", "zstd", "lzo",
            // RAID / device mapper
            "md_mod", "raid0", "raid1", "raid5", "raid6", "dm_mod", "dm_crypt",
            // NFS / CIFS
            "nfs", "nfsd", "lockd", "sunrpc", "cifs", "smb",
            // Network tunneling
            "vxlan", "geneve", "xfrm_user", "xfrm_algo",
            // Intel platform
            "intel_cstate", "intel_powerclamp", "intel_rapl_msr", "intel_rapl_common",
            "intel_uncore_frequency", "intel_uncore_frequency_common",
            "intel_soc_dts_iosf", "intel_pmc_core", "intel_vsec", "intel_hid",
            "intel_lpss", "intel_lpss_pci", "intel_ishtp", "intel_ishtp_hid",
            "intel_ish_ipc", "intel_pxp", "intel_hdcp",
            // Intel thermal
            "x86_pkg_temp_thermal", "coretemp", "processor_thermal_device",
            "processor_thermal_device_pci_legacy", "processor_thermal_wt_hint",
            "processor_thermal_wt_req", "processor_thermal_rfim", "processor_thermal_rapl",
            "processor_thermal_power_floor", "processor_thermal_mbox",
            "int3403_thermal", "int340x_thermal_zone", "int3400_thermal", "acpi_thermal_rel",
            // Intel CPU
            "rapl", "msr", "intel_pmc_core",
            // Intel ME
            "mei", "mei_me",
            // Intel storage
            "spi_intel", "spi_intel_pci", "spi_pxa2xx_platform", "8250_dw",
            // Misc Intel
            "pmt_telemetry", "pmt_class", "intel_vsec", "intel_soc_dts_iosf",
            // HP specific
            "hp_wmi", "hp_bioscfg",
            // ACPI / platform
            "wmi", "wmi_bmof", "sparse_keymap", "soc_button_array", "video",
            "acpi_pad", "platform_profile", "firmware_attributes_class",
            // Input
            "joydev", "serio_raw", "input_leds", "ledtrig_audio", "rc_core",
            // I2C
            "i2c_i801", "i2c_hid", "i2c_hid_acpi", "i2c_algo_bit", "i2c_smbus",
            // DMA
            "dw_dmac", "dw_dmac_core", "idma64",
            // Type-C / USB-PD
            "typec", "typec_ucsi", "ucsi_acpi",
            // Storage controller
            "vmd", "xhci_pci", "xhci_pci_renesas",
            // Misc
            "binfmt_misc", "autofs4", "efi_pstore", "dmi_sysfs", "nls_iso8859_1",
            "crc32c_generic", "libcrc32c", "crc32_pclmul",
            "irqbypass", "machreboot",
            // Crypto accelerated
            "crypto_simd",
            // Industrial IO
            "industrialio", "industrialio_triggered_buffer", "kfifo_buf",
            // EDAC (error detection)
            "igen6_edac",
            // Parport (legacy)
            "parport", "parport_pc", "ppdev", "lp",
            // Webcam / media
            "cec",
            // FPGA
            "qrtr",
            // Qualcomm
            "qcom_spmi regulator",
            // HID sensors
            "hid_sensor_custom", "hid_sensor_custom_intel_hinge",
            "hid_sensor_incl_3d", "hid_sensor_rotation", "hid_sensor_gyro_3d",
            // DMA Intel
            "spi_pxa2xx_platform",
            // Crypto hardware
            "cryptd",
            // Thunderbolt
            "thunderbolt",
            // Netfilter
            "nf_conntrack_netlink",
            // More legitimate modules
            "crct10dif_pclmul", "cmdlinepart", "ee1004", "libarc4", "ecc",
            "mac_hid", "sch_fq_codel", "pinctrl_tigerlake",
            "snd_seq_dummy", "snd_ctl_led", "snd_sof_probes", "snd_sof_pci_intel_tgl",
            "snd_seq_midi", "mei_pxp", "mei_hdcp",
        ].into_iter().map(String::from).collect()
    }

    pub fn scan(&self) -> Result<KernelReport> {
        info!("Starting kernel module scan");
        let mut findings = Vec::new();

        // Get kernel version
        let kernel_version = self.get_kernel_version()?;

        // Load modules
        let modules = self.load_modules()?;

        // Check for suspicious modules
        for module in &modules {
            if !self.is_whitelisted(&module.name) {
                findings.push(KernelFinding {
                    module: module.name.clone(),
                    finding_type: "Unknown Module".to_string(),
                    severity: "High".to_string(),
                    description: format!("Non-whitelisted kernel module loaded: {}", module.name),
                    details: Some(format!("Size: {}, RefCount: {}", module.size, module.ref_count)),
                });
            }

            // Check for zero ref count (suspicious)
            if module.ref_count == 0 {
                findings.push(KernelFinding {
                    module: module.name.clone(),
                    finding_type: "Unreferenced Module".to_string(),
                    severity: "Medium".to_string(),
                    description: format!("Module {} has zero reference count", module.name),
                    details: None,
                });
            }
        }

        // Check for known rootkit modules
        findings.extend(self.check_known_rootkits(&modules));

        let score = self.calculate_score(&findings);
        let summary = self.generate_summary(&findings, score, &kernel_version);

        info!("Kernel scan completed: {} findings, score: {}", findings.len(), score);

        Ok(KernelReport {
            timestamp: chrono::Utc::now().to_rfc3339(),
            kernel_version,
            loaded_modules: modules,
            findings,
            score,
            summary,
        })
    }

    fn get_kernel_version(&self) -> Result<String> {
        let content = std::fs::read_to_string("/proc/version")?;
        Ok(content.trim().to_string())
    }

    fn load_modules(&self) -> Result<Vec<KernelModule>> {
        let mut modules = Vec::new();

        let content = std::fs::read_to_string("/proc/modules")?;
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                modules.push(KernelModule {
                    name: parts[0].to_string(),
                    size: parts[1].parse().unwrap_or(0),
                    ref_count: parts[2].parse().unwrap_or(0),
                    loaded_at: None,
                });
            }
        }

        Ok(modules)
    }

    fn is_whitelisted(&self, name: &str) -> bool {
        self.whitelisted_modules.iter().any(|w| name.starts_with(w))
    }

    fn check_known_rootkits(&self, modules: &[KernelModule]) -> Vec<KernelFinding> {
        let mut findings = Vec::new();

        // Use exact module names only (not substring) to avoid false positives
        let known_rootkits = [
            "diamorphine", "reptile", "kovi", "suckit", "knark",
            "adore", "adore-ng", "hide_lkm", "heroin", "override",
            "_klapper", "enye_lkm", "fu_mod", "rial_mod", "nodrv",
        ];

        for module in modules {
            let name_lower = module.name.to_lowercase();
            for &rootkit in &known_rootkits {
                // Exact name match OR ends with -rootkit suffix
                if name_lower == rootkit || name_lower == format!("{}.ko", rootkit) {
                    findings.push(KernelFinding {
                        module: module.name.clone(),
                        finding_type: "Known Rootkit".to_string(),
                        severity: "Critical".to_string(),
                        description: format!("Known rootkit module detected: {}", module.name),
                        details: Some(format!("Exact match: {}", rootkit)),
                    });
                }
            }
        }

        findings
    }

    fn calculate_score(&self, findings: &[KernelFinding]) -> u32 {
        let mut score = 0;
        for finding in findings {
            match finding.severity.as_str() {
                "Critical" => score += 50,
                "High" => score += 30,
                "Medium" => score += 15,
                "Low" => score += 5,
                _ => {}
            }
        }
        score.min(100)
    }

    fn generate_summary(
        &self,
        findings: &[KernelFinding],
        score: u32,
        kernel_version: &str,
    ) -> String {
        if findings.is_empty() {
            format!("Kernel clean. {} modules loaded. No suspicious modules detected.", self.whitelisted_modules.len())
        } else {
            let critical = findings.iter().filter(|f| f.severity == "Critical").count();
            let high = findings.iter().filter(|f| f.severity == "High").count();

            format!(
                "Kernel {} has {} suspicious modules ({} critical, {} high). Risk score: {}/100",
                kernel_version, findings.len(), critical, high, score
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = KernelScanner::new();
        assert!(!scanner.whitelisted_modules.is_empty());
    }

    #[test]
    fn test_whitelist() {
        let scanner = KernelScanner::new();
        assert!(scanner.is_whitelisted("ext4"));
        assert!(scanner.is_whitelisted("nf_conntrack"));
        assert!(!scanner.is_whitelisted("diamorphine"));
    }

    #[test]
    fn test_calculate_score_empty() {
        let scanner = KernelScanner::new();
        let score = scanner.calculate_score(&vec![]);
        assert_eq!(score, 0);
    }
}
