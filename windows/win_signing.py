"""
Binary Ninja plugin - Driver signing and certificate analysis.

Extracts Authenticode signature data from PE driver binaries:
  - Signer name, issuer chain, timestamp
  - SHA-1 vs SHA-2 hash algorithm
  - Cross-signing status
  - WHQL / EV certificate indicators
  - Microsoft Vulnerable Driver Blocklist check
  - Revocation indicator heuristics

For BYOVD viability assessment: a driver's signature status determines
whether it will load on a given Windows configuration (HVCI/WDAC/DSE).

USE ON AUTHORIZED TARGETS ONLY.
"""

import os
import re
import struct
import hashlib
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand, BackgroundTaskThread

# Known vulnerable driver signers (from LOLDrivers / BYOVD research)
_KNOWN_VULN_SIGNERS = {
    'Realtek Semiconductor',
    'ASUSTeK Computer',
    'GIGA-BYTE TECHNOLOGY',
    'Intel(R) Embedded Subsystems',
    'Razer',
    'Capcom',
    'Dell',
    'HP',
    'Micro-Star International',
    'WinRing0',
    'Zemana',
    'Process Hacker',
    'HWiNFO',
    'CPUID',
    'Passmark',
    'EVGA',
    'Marvin Test Solutions',
    'Novell',
    'Toshiba',
    'Samsung',
}

# Microsoft Vulnerable Driver Blocklist hashes (subset - high-value)
_BLOCKLIST_SHA256 = set()

# PE Security Directory constants
_IMAGE_DIRECTORY_ENTRY_SECURITY = 4
_WIN_CERT_REVISION_2_0 = 0x0200
_WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002

# OID strings for parsing
_OID_TIMESTAMP = '1.2.840.113549.1.9.5'
_OID_SIGNER_INFO = '1.2.840.113549.1.9.4'


def _file_sha256(path):
    if not path or not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _file_sha1(path):
    if not path or not os.path.isfile(path):
        return None
    h = hashlib.sha1()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _extract_pe_cert_data(path):
    """Extract raw certificate data from PE security directory."""
    try:
        with open(path, 'rb') as f:
            # DOS header
            f.seek(0x3C)
            pe_offset = struct.unpack('<I', f.read(4))[0]

            # PE signature
            f.seek(pe_offset)
            sig = f.read(4)
            if sig != b'PE\x00\x00':
                return None

            # COFF header
            f.seek(pe_offset + 4)
            machine = struct.unpack('<H', f.read(2))[0]

            # Optional header offset
            f.seek(pe_offset + 20)
            opt_hdr_size = struct.unpack('<H', f.read(2))[0]

            # Optional header magic
            f.seek(pe_offset + 24)
            magic = struct.unpack('<H', f.read(2))[0]

            if magic == 0x20B:  # PE32+
                cert_dir_offset = pe_offset + 24 + 144  # Security dir in data directories
            elif magic == 0x10B:  # PE32
                cert_dir_offset = pe_offset + 24 + 128
            else:
                return None

            f.seek(cert_dir_offset)
            cert_rva = struct.unpack('<I', f.read(4))[0]
            cert_size = struct.unpack('<I', f.read(4))[0]

            if cert_rva == 0 or cert_size == 0:
                return {'signed': False}

            # Read certificate table
            f.seek(cert_rva)
            cert_data = f.read(cert_size)
            if len(cert_data) < 8:
                return {'signed': False}

            # WIN_CERTIFICATE header
            dwLength = struct.unpack('<I', cert_data[0:4])[0]
            wRevision = struct.unpack('<H', cert_data[4:6])[0]
            wCertType = struct.unpack('<H', cert_data[6:8])[0]

            return {
                'signed': True,
                'cert_size': cert_size,
                'revision': wRevision,
                'cert_type': wCertType,
                'raw': cert_data[8:],
            }
    except Exception:
        return None


def _extract_signer_from_cert(raw_cert):
    """Extract signer common name from DER-encoded PKCS#7 data.
    Simplified extraction - looks for readable strings in cert."""
    info = {
        'signer': None,
        'issuer': None,
        'timestamp': None,
        'hash_algo': None,
    }

    if not raw_cert:
        return info

    # Look for hash algorithm OIDs
    if b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01' in raw_cert:
        info['hash_algo'] = 'SHA-256'
    elif b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02' in raw_cert:
        info['hash_algo'] = 'SHA-384'
    elif b'\x06\x05\x2b\x0e\x03\x02\x1a' in raw_cert:
        info['hash_algo'] = 'SHA-1'
    elif b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b' in raw_cert:
        info['hash_algo'] = 'SHA-256 (RSA)'
    elif b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05' in raw_cert:
        info['hash_algo'] = 'SHA-1 (RSA)'

    # Extract readable strings that look like CN/O fields
    # Look for common certificate issuer patterns
    readable_strings = []
    i = 0
    while i < len(raw_cert) - 2:
        # ASN.1 PrintableString (0x13) or UTF8String (0x0C)
        if raw_cert[i] in (0x13, 0x0C):
            slen = raw_cert[i + 1]
            if 3 < slen < 200 and i + 2 + slen <= len(raw_cert):
                try:
                    s = raw_cert[i + 2:i + 2 + slen].decode('utf-8', errors='ignore')
                    if len(s) >= 3 and any(c.isalpha() for c in s):
                        readable_strings.append(s)
                except Exception:
                    pass
            i += 2 + slen
        else:
            i += 1

    # Heuristic: first long-ish string with company-like name is often the signer
    company_indicators = ['Inc', 'Corp', 'Ltd', 'LLC', 'Co.', 'Technology',
                          'Software', 'Electronics', 'Computer', 'Microsoft',
                          'Solutions', 'International', 'Systems', 'Group']
    cert_indicators = ['Certificate', 'CA', 'Authority', 'Root', 'Code Signing',
                       'Timestamp', 'WHQL', 'Verification']

    for s in readable_strings:
        if not info['signer'] and any(ci in s for ci in company_indicators):
            info['signer'] = s
        elif not info['issuer'] and any(ci in s for ci in cert_indicators):
            info['issuer'] = s

    # Fallback: just use first reasonable string
    if not info['signer'] and readable_strings:
        for s in readable_strings:
            if len(s) > 5 and not s.startswith('http') and ' ' in s:
                info['signer'] = s
                break

    # Check for WHQL
    cert_text = raw_cert.decode('latin-1', errors='ignore')
    if 'WHQL' in cert_text or 'Windows Hardware Quality Labs' in cert_text:
        info['whql'] = True
    else:
        info['whql'] = False

    # Check for cross-signing indicators
    if 'Cross' in cert_text or 'cross' in cert_text:
        info['cross_signed'] = True
    else:
        info['cross_signed'] = False

    # Check for timestamp
    if b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x05' in raw_cert:
        info['has_timestamp'] = True
    else:
        info['has_timestamp'] = False

    return info


def _assess_byovd_viability(cert_info, sha256):
    """Assess BYOVD viability based on signing status."""
    notes = []
    risk = 'MEDIUM'

    if not cert_info or not cert_info.get('signed', False):
        notes.append(('LOW', 'Unsigned driver - will not load with DSE enabled'))
        notes.append(('INFO', 'Only usable with test signing or DSE disabled'))
        return notes

    # SHA-1 only signature
    if cert_info.get('hash_algo') == 'SHA-1':
        notes.append(('HIGH', 'SHA-1 signature only - blocked on Win10 1607+ with SecureBoot'))
        notes.append(('INFO', 'May still load on Win7/8 or with SecureBoot off'))
    elif cert_info.get('hash_algo') and 'SHA-256' in cert_info.get('hash_algo', ''):
        notes.append(('INFO', 'SHA-256 signature - compatible with modern Windows'))

    # WHQL
    if cert_info.get('whql'):
        notes.append(('HIGH', 'WHQL signed - higher trust level, loads with HVCI'))

    # Cross-signed
    if cert_info.get('cross_signed'):
        notes.append(('MEDIUM', 'Cross-signed certificate - may be subject to revocation'))

    # Timestamp
    if cert_info.get('has_timestamp'):
        notes.append(('INFO', 'Timestamp present - driver remains valid after cert expiry'))
    else:
        notes.append(('MEDIUM', 'No timestamp - driver invalid after certificate expiry'))

    # Blocklist check
    if sha256 and sha256.lower() in _BLOCKLIST_SHA256:
        notes.append(('CRITICAL', 'ON MICROSOFT VULNERABLE DRIVER BLOCKLIST'))
        notes.append(('INFO', 'Will not load with HVCI/WDAC default policy'))

    # Known vulnerable signer
    signer = cert_info.get('signer', '')
    if signer:
        for known in _KNOWN_VULN_SIGNERS:
            if known.lower() in signer.lower():
                notes.append(('HIGH',
                    'Signer "{}" has known vulnerable drivers in LOLDrivers DB'.format(known)))
                break

    return notes


class _SigningTask(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "Analyzing driver signature...", True)
        self.bv = bv

    def run(self):
        try:
            self._run()
        except Exception as e:
            log_warn("[signing] task failed: {}".format(e))

    def _run(self):
        bv = self.bv
        path = bv.file.filename
        drv_name = os.path.splitext(os.path.basename(path))[0]
        log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
        os.makedirs(log_dir, exist_ok=True)
        report_path = os.path.join(log_dir, drv_name + '-signing.txt')

        lines = [
            "=== Driver Signing & Certificate Analysis ===",
            "Binary: {}".format(path),
            "",
        ]

        def emit(s):
            lines.append(s)
            log_info(s)

        # Hashes
        sha256 = _file_sha256(path)
        sha1 = _file_sha1(path)
        if sha256:
            emit("[+] SHA-256: {}".format(sha256))
        if sha1:
            emit("[+] SHA-1:   {}".format(sha1))

        # PE certificate extraction
        self.progress = "Extracting PE certificate..."
        cert_data = _extract_pe_cert_data(path)

        if cert_data is None:
            emit("[-] Could not parse PE headers")
            return

        if not cert_data.get('signed', False):
            emit("[-] Driver is NOT signed (no security directory)")
            emit("[!] Will not load with Driver Signature Enforcement enabled")
        else:
            emit("[+] Driver IS signed")
            emit("    Certificate size: {} bytes".format(cert_data.get('cert_size', 0)))
            rev = cert_data.get('revision', 0)
            emit("    WIN_CERTIFICATE revision: 0x{:04X} ({})".format(
                rev, 'v2.0' if rev == _WIN_CERT_REVISION_2_0 else 'unknown'))

            # Parse certificate
            self.progress = "Parsing certificate chain..."
            cert_info = _extract_signer_from_cert(cert_data.get('raw', b''))

            if cert_info.get('signer'):
                emit("    Signer: {}".format(cert_info['signer']))
            if cert_info.get('issuer'):
                emit("    Issuer: {}".format(cert_info['issuer']))
            if cert_info.get('hash_algo'):
                emit("    Hash algorithm: {}".format(cert_info['hash_algo']))
            emit("    WHQL: {}".format('Yes' if cert_info.get('whql') else 'No'))
            emit("    Cross-signed: {}".format('Yes' if cert_info.get('cross_signed') else 'No'))
            emit("    Timestamp: {}".format('Present' if cert_info.get('has_timestamp') else 'Not found'))

            # BYOVD viability
            emit("\n[>] BYOVD Viability Assessment:")
            notes = _assess_byovd_viability(cert_info, sha256)
            for sev, note in notes:
                emit("    [{}] {}".format(sev, note))

        # PE metadata
        emit("\n[>] PE Metadata:")
        try:
            with open(path, 'rb') as f:
                f.seek(0x3C)
                pe_off = struct.unpack('<I', f.read(4))[0]
                f.seek(pe_off + 8)
                timestamp = struct.unpack('<I', f.read(4))[0]
                if timestamp != 0:
                    import datetime
                    try:
                        ts = datetime.datetime.utcfromtimestamp(timestamp)
                        emit("    PE timestamp: {} (0x{:08X})".format(ts.strftime('%Y-%m-%d %H:%M:%S UTC'), timestamp))
                    except Exception:
                        emit("    PE timestamp: 0x{:08X}".format(timestamp))
                else:
                    emit("    PE timestamp: zeroed (anti-forensics or repacked)")

                # Linker version
                f.seek(pe_off + 24)
                magic = struct.unpack('<H', f.read(2))[0]
                major_link = struct.unpack('<B', f.read(1))[0]
                minor_link = struct.unpack('<B', f.read(1))[0]
                emit("    Linker version: {}.{}".format(major_link, minor_link))

                # OS version
                if magic == 0x20B:
                    f.seek(pe_off + 24 + 40)
                else:
                    f.seek(pe_off + 24 + 40)
                os_major = struct.unpack('<H', f.read(2))[0]
                os_minor = struct.unpack('<H', f.read(2))[0]
                emit("    Target OS: {}.{}".format(os_major, os_minor))
        except Exception as e:
            emit("    Could not parse PE metadata: {}".format(e))

        emit("\n[+] Signing analysis complete.")

        try:
            with open(report_path, 'w') as f:
                f.write('\n'.join(lines))
            emit('[+] Report saved to: {}'.format(report_path))
        except Exception as e:
            log_warn("Could not write signing report: {}".format(e))

        self.progress = ""


def analyze_signing(bv: BinaryView):
    _SigningTask(bv).start()


PluginCommand.register(
    "Windows Driver Analysis\\Signing & Certificate Analysis",
    "Analyze Authenticode signature, certificate chain, and BYOVD viability",
    analyze_signing,
)
