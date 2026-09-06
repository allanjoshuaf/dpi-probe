"""Dependency checks that use only the Python standard library."""
import importlib
import importlib.metadata
import shutil
import sys


def python_issues():
    issues = []
    if sys.version_info < (3, 11):
        issues.append('Python 3.11 or newer is required')
    for package, module, lower, upper in [('cryptography', 'cryptography', (42,), (49,)),
                                           ('dnspython', 'dns.resolver', (2, 6), (3,))]:
        try:
            importlib.import_module(module)
            version = importlib.metadata.version(package)
            numbers = tuple(int(x) for x in version.split('.') if x.isdigit())
            if not lower <= numbers < upper:
                issues.append(f'{package}: installed version {version} is outside requirements.txt')
        except (ImportError, importlib.metadata.PackageNotFoundError):
            issues.append(f'{package} is missing or cannot be imported')
    return issues


def doctor():
    from src.pcap import find_tshark, list_interfaces
    issues = python_issues()
    print('Python modules: ' + ('OK' if not issues else '; '.join(issues)))
    tshark = find_tshark()
    print('TShark: ' + ('available' if tshark else 'MISSING: install Wireshark with TShark'))
    interfaces = list_interfaces() if tshark else []
    print('Capture interfaces: ' + ('available (capture permissions still checked when starting)' if interfaces else 'UNAVAILABLE: check Npcap/libpcap and capture permissions'))
    print('curl: ' + ('available; ECH support depends on the build' if shutil.which('curl') else 'missing; required only for active ECH'))
    print('ssh: ' + ('available' if shutil.which('ssh') else 'missing; required only for reverse trace'))
    print('Missing capabilities are not evidence of network filtering. No network probes were sent.')
    return not issues and bool(tshark) and bool(interfaces)
