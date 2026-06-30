# CHIPSEC Custom Module for Sharif University IoT Lab
# Module to check if secureboot is enabled but UEFIShell is bootable, which can be used to bypass
# secureboot. See CVE-2023-48733.
# Requirements:
# - Guest Linux OS running inside QEMU
# - QEMU booting via OVMF
# - `chipsec.ko` signed by MOK
# Expected Behaviour:
# - `ovmf_2022.08-1_all.deb` should FAIL
# - `ovmf_2022.11-6+deb12u2_all.deb` should PASS
# - If secureboot is not enabled, neither FAIL nor PASS

from chipsec.module_common import *
from chipsec.hal.uefi import UEFI, EFI_VAR_NAME_SecureBoot

import uuid

EFI_GLOBAL_VARIABLE_GUID = '8BE4DF61-93CA-11D2-AA0D-00E098032B8C'
FULLSHELL_GUID = '7C04A583-9E3E-4F1C-AD65-E05268D0B4D1'

class secureboot_fullshell(BaseModule):
    def __init__(self):
        BaseModule.__init__(self)
        self.name = "Secure Boot Full Shell Presence Check"
        self.description = "Checks if Secure Boot is enabled but a UEFI shell (FULLSHELL_GUID) is embedded in firmware, allowing a potential bypass"
        self.config_required = False
        self._uefi = None

    def is_supported(self):
        return True

    def run(self, module_argv):
        self._uefi = UEFI(self.cs)

        data = self._uefi.get_EFI_variable(EFI_VAR_NAME_SecureBoot, EFI_GLOBAL_VARIABLE_GUID)
        secureboot_enabled = (data is not None) and (len(data) == 1) and (data[0] == 0x1)

        if not secureboot_enabled:
            self.logger.log_warning("Secure Boot is not enabled — skipping shell presence check")
            return ModuleResult.WARNING

        FLASH_BASE = 0xFFC00000   # 4M build; OVMF_CODE_4M.secboot.fd
        FLASH_SIZE = 0x400000
        fw = bytes(self.cs.mem.read_physical_mem(FLASH_BASE, FLASH_SIZE))

        shell_present = uuid.UUID(FULLSHELL_GUID).bytes_le in fw

        if secureboot_enabled and shell_present:
            self.logger.log_failed("Secure Boot is enabled but UEFI Full Shell (FULLSHELL_GUID) is present in firmware — shell can be used to bypass Secure Boot")
            return ModuleResult.FAILED
        else:
            self.logger.log_passed("Secure Boot is enabled and no unauthorized UEFI Full Shell was found in firmware")
            return ModuleResult.PASSED
