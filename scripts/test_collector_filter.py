#!/usr/bin/env python3
"""Verify the NOISY_FILE_PATHS filter works correctly."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from collector import should_forward, NOISY_FILE_PATHS

tests = [
    # (TargetFilename, expected_result, label)
    (r'C:\Users\thome\AppData\Local\Programs\Microsoft VS Code\08d4889f9e\resources\app\extensions\shaderlab\syntaxes\is-3MAHL.tmp', False, 'VS Code tmp'),
    (r'C:\Users\thome\AppData\Local\Google Chrome\User Data\Default\Cache\Cache_Data\f_000654', False, 'Chrome cache'),
    (r'C:\Users\thome\AppData\Roaming\discord\sentry\scope_v3.json', False, 'Discord sentry'),
    (r'C:\Users\thome\AppData\Local\Temp\DiagOutputDir\RdClientAutoTrace\MSRDCEventProcessor_2.etl', False, 'Temp ETL'),
    (r'C:\Users\thome\Documents\Codex\2026-04-27\act-as-a-senior-security-architect-3\.collector_state.json', False, 'collector_state'),
    (r'C:\Users\thome\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive', False, 'PowerShell startup'),
    (r'C:\Windows\Installer\somesetup.msi', False, 'Windows Installer MSI'),
    (r'C:\Users\Public\malware.exe', True, 'Suspicious .exe'),
    (r'C:\Users\thome\Desktop\suspicious_payload.exe', True, 'Desktop .exe'),
    (r'C:\Temp\malware.dll', True, 'Temp malware.dll'),
]

all_pass = True
for path, expected, label in tests:
    event = {'Id': 11, 'Data': {'TargetFilename': path}}
    result = should_forward('Microsoft-Windows-Sysmon/Operational', event)
    status = 'PASS' if result == expected else 'FAIL'
    if status == 'FAIL':
        all_pass = False
    print(f'{status}: {label} -> {result} (expected {expected})')

# Test other event IDs still work
reg_event = {'Id': 13, 'Data': {}}
result = should_forward('Microsoft-Windows-Sysmon/Operational', reg_event)
status = 'PASS' if result == True else 'FAIL'
if status == 'FAIL':
    all_pass = False
print(f'{status}: Registry event 13')

# Verify NOISY_FILE_PATHS count
print(f'\nNOISY_FILE_PATHS has {len(NOISY_FILE_PATHS)} patterns')
print('All tests passed!' if all_pass else 'Some tests FAILED!')