"""
Binary Ninja plugin - Structured JSON/SARIF report output.

Consolidates all analysis results (vulnerabilities, primitives, IOCTL map,
IRP handlers, device names, LOLDrivers matches, DACL, FastIO) into a
single structured JSON report. Optionally exports SARIF 2.1.0 for
integration with GitHub code scanning, VS Code, and DefectDojo.

Output: ~/.logs/WinDriverVulns/<driver>-report.json
        ~/.logs/WinDriverVulns/<driver>-report.sarif

USE ON AUTHORIZED TARGETS ONLY.
"""

import os
import json
import time
import hashlib
from binaryninja import BinaryView, log_info, log_warn
from binaryninja.plugin import PluginCommand, BackgroundTaskThread

from ..shared.helpers import get_hlil_text, get_callers
from .win_vuln_finder import (
    _find_dispatch_routines, _ioctl_branches_for_dispatcher,
    _find_ioctls, _ctl_decode, METHOD_MAP, ACCESS_MAP,
    _classify_branch_vulns, _resolve_callee_name,
    _collect_pooltags, _looks_user_driven_win, _is_ioctl_context,
)

# CWE mapping for detected vulnerability classes
_CWE_MAP = {
    'Write-What-Where':             'CWE-123',
    'Arbitrary Kernel Read':        'CWE-125',
    'MSR Read/Write Primitive':     'CWE-782',
    'Port IO Primitive':            'CWE-782',
    'Physical Memory Map':          'CWE-782',
    'Control/Debug Register Access':'CWE-782',
    'Ring-0 Exec (Capcom-style)':   'CWE-94',
    'PCI Config Space Access':      'CWE-782',
    'Stack Buffer Overflow':        'CWE-121',
    'Pool Buffer Overflow':         'CWE-122',
    'NULL Pointer Deref':           'CWE-476',
    'Token-Swap Primitive':         'CWE-269',
    'Type Confusion (Object)':      'CWE-843',
    'Double-Fetch TOCTOU':          'CWE-367',
    'Uninitialized Pool Leak':      'CWE-908',
    'memcpy':                       'CWE-120',
    'RtlCopyMemory':                'CWE-120',
    'MmMapIoSpace':                 'CWE-782',
    'MmCopyMemory':                 'CWE-782',
    'rdmsr':                        'CWE-782',
    'wrmsr':                        'CWE-782',
    'Missing privilege gate':       'CWE-862',
    'IoCreateDevice without IoCreateDeviceSecure': 'CWE-732',
}

_SEVERITY_RANK = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}


def _file_sha256(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _collect_device_names(bv):
    names = []
    indicators = ["\\device\\", "\\dosdevices\\", "\\\\.\\", "\\??\\"]
    for s in bv.strings:
        try:
            val = s.value
            if any(k in val.lower() for k in indicators):
                names.append({'value': val, 'address': s.start})
        except Exception:
            pass
    return names


def _collect_ioctl_map(bv):
    ioctls = []
    seen = set()
    dispatchers = _find_dispatch_routines(bv)
    for df in dispatchers:
        branches = _ioctl_branches_for_dispatcher(df)
        by_code = {}
        for code, instrs, addr in branches:
            by_code.setdefault(code, []).extend(instrs)
        for code, instrs in by_code.items():
            if code in seen:
                continue
            seen.add(code)
            d = _ctl_decode(code)
            vulns, callees = _classify_branch_vulns(bv, instrs)
            callee_names = sorted({_resolve_callee_name(bv, c) for c in callees})
            ioctls.append({
                'code': '0x{:08X}'.format(code),
                'code_int': code,
                'device': d['device'],
                'function': d['function'],
                'method': METHOD_MAP.get(d['method'], str(d['method'])),
                'access': ACCESS_MAP.get(d['access'], str(d['access'])),
                'dispatcher': df.name,
                'callees': callee_names[:12],
                'vuln_labels': sorted(vulns),
            })
    return sorted(ioctls, key=lambda x: x['code_int'])


def _collect_findings(bv):
    """Run all vulnerability checks and return structured findings."""
    findings = []
    finding_id = 0

    dispatchers = _find_dispatch_routines(bv)
    for df in dispatchers:
        branches = _ioctl_branches_for_dispatcher(df)
        by_code = {}
        for code, instrs, addr in branches:
            by_code.setdefault(code, []).extend(instrs)
        for code, instrs in by_code.items():
            vulns, callees = _classify_branch_vulns(bv, instrs)
            d = _ctl_decode(code)
            method = METHOD_MAP.get(d['method'], str(d['method']))
            for vlabel in vulns:
                finding_id += 1
                # Determine base label for CWE lookup
                base_label = vlabel.split(' (via ')[0] if ' (via ' in vlabel else vlabel
                cwe = _CWE_MAP.get(base_label, 'CWE-693')
                sev = 'HIGH'
                if any(k in base_label for k in ['CRITICAL', 'MSR', 'Physical', 'Ring-0', 'Write-What-Where', 'Token']):
                    sev = 'CRITICAL'
                elif any(k in base_label for k in ['Stack', 'Pool', 'Type Confusion', 'Double']):
                    sev = 'HIGH'
                elif 'NULL' in base_label or 'Uninit' in base_label:
                    sev = 'MEDIUM'

                findings.append({
                    'id': 'DRV-{:04d}'.format(finding_id),
                    'severity': sev,
                    'cwe': cwe,
                    'title': base_label,
                    'detail': vlabel,
                    'ioctl': '0x{:08X}'.format(code),
                    'method': method,
                    'dispatcher': df.name,
                    'dispatcher_addr': '0x{:x}'.format(df.start),
                    'confidence': 'high' if '(name)' not in vlabel else 'medium',
                })

    return sorted(findings, key=lambda f: _SEVERITY_RANK.get(f['severity'], 9))


def _build_json_report(bv):
    path = None
    try:
        path = bv.file.original_filename or bv.file.filename
    except Exception:
        path = bv.file.filename

    report = {
        'tool': 'BinjaKernelTools',
        'version': '1.0',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'binary': {
            'filename': os.path.basename(path) if path else 'unknown',
            'path': path,
            'sha256': _file_sha256(path),
        },
        'device_names': _collect_device_names(bv),
        'pool_tags': {tag: sorted(funcs) for tag, funcs in _collect_pooltags(bv).items()},
        'ioctls': _collect_ioctl_map(bv),
        'findings': _collect_findings(bv),
    }

    # Summary stats
    findings = report['findings']
    report['summary'] = {
        'total_findings': len(findings),
        'critical': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
        'high': sum(1 for f in findings if f['severity'] == 'HIGH'),
        'medium': sum(1 for f in findings if f['severity'] == 'MEDIUM'),
        'low': sum(1 for f in findings if f['severity'] == 'LOW'),
        'total_ioctls': len(report['ioctls']),
        'total_device_names': len(report['device_names']),
    }

    return report


def _build_sarif(report):
    """Convert internal report to SARIF 2.1.0 format."""
    rules = {}
    results = []

    for f in report['findings']:
        rule_id = f['cwe']
        if rule_id not in rules:
            rules[rule_id] = {
                'id': rule_id,
                'shortDescription': {'text': f['title']},
                'helpUri': 'https://cwe.mitre.org/data/definitions/{}.html'.format(
                    rule_id.replace('CWE-', '')),
            }

        severity_map = {'CRITICAL': 'error', 'HIGH': 'error', 'MEDIUM': 'warning', 'LOW': 'note'}
        results.append({
            'ruleId': rule_id,
            'level': severity_map.get(f['severity'], 'warning'),
            'message': {
                'text': '{} in IOCTL {} ({}) - {}'.format(
                    f['title'], f['ioctl'], f['method'], f['detail']),
            },
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {
                        'uri': report['binary']['filename'],
                    },
                },
                'logicalLocations': [{
                    'name': f['dispatcher'],
                    'kind': 'function',
                }],
            }],
            'properties': {
                'findingId': f['id'],
                'severity': f['severity'],
                'ioctl': f['ioctl'],
                'method': f['method'],
                'confidence': f['confidence'],
            },
        })

    sarif = {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'BinjaKernelTools',
                    'version': '1.0',
                    'rules': list(rules.values()),
                },
            },
            'results': results,
            'invocations': [{
                'executionSuccessful': True,
                'endTimeUtc': report['timestamp'],
            }],
        }],
    }

    return sarif


class _ReportTask(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "Generating structured report...", True)
        self.bv = bv

    def run(self):
        try:
            self._run()
        except Exception as e:
            log_warn("[report] task failed: {}".format(e))
            import traceback
            log_warn(traceback.format_exc())

    def _run(self):
        bv = self.bv
        drv = os.path.splitext(os.path.basename(bv.file.filename))[0]
        log_dir = os.path.join(os.path.expanduser('~'), '.logs', 'WinDriverVulns')
        os.makedirs(log_dir, exist_ok=True)

        self.progress = "Building report..."
        report = _build_json_report(bv)

        # Write JSON
        json_path = os.path.join(log_dir, drv + '-report.json')
        try:
            with open(json_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            log_info("[report] JSON: {}".format(json_path))
        except Exception as e:
            log_warn("[report] JSON write failed: {}".format(e))

        # Write SARIF
        self.progress = "Building SARIF..."
        sarif = _build_sarif(report)
        sarif_path = os.path.join(log_dir, drv + '-report.sarif')
        try:
            with open(sarif_path, 'w') as f:
                json.dump(sarif, f, indent=2)
            log_info("[report] SARIF: {}".format(sarif_path))
        except Exception as e:
            log_warn("[report] SARIF write failed: {}".format(e))

        # Summary
        s = report['summary']
        log_info("[report] Complete: {} findings ({} CRITICAL, {} HIGH, {} MEDIUM), {} IOCTLs".format(
            s['total_findings'], s['critical'], s['high'], s['medium'], s['total_ioctls']))

        self.progress = ""


def generate_report(bv: BinaryView):
    _ReportTask(bv).start()


PluginCommand.register(
    "Windows Driver Analysis\\Generate Report (JSON + SARIF)",
    "Export all findings as structured JSON and SARIF 2.1.0",
    generate_report,
)
