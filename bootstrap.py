"""Create a private environment and offer dependency installation before launch."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import venv
import webbrowser

ROOT = Path(__file__).resolve().parent


def consent(message):
    return input(message + ' [y/N] ').strip().lower() in ('y', 'yes', 'o', 'oui')


def main():
    if sys.version_info < (3, 11):
        print('Python 3.11+ required. Install from https://www.python.org/downloads/ and restart.')
        return 2
    os.chdir(ROOT)
    environment = ROOT / '.venv'
    python = environment / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    if not python.is_file():
        if not consent('Create .venv and install Python dependencies / Installer les dépendances Python ?'):
            print('Installation cancelled. No measurements started.')
            return 2
        try:
            venv.EnvBuilder(with_pip=True).create(environment)
        except (OSError, subprocess.CalledProcessError):
            if sys.platform.startswith('linux') and shutil.which('apt-get') and consent('Install missing system venv/pip packages and retry?'):
                prefix = [] if os.geteuid() == 0 else ['sudo']
                subprocess.run(prefix + ['apt-get', 'install', 'python3-venv', 'python3-pip'], check=True)
                venv.EnvBuilder(with_pip=True).create(environment)
            else:
                raise
        subprocess.run([str(python), '-m', 'pip', 'install', '-r', str(ROOT / 'requirements.txt')], check=True)
    check = subprocess.run([str(python), '-c', 'from src.preflight import python_issues; import sys; x=python_issues(); print("; ".join(x)); sys.exit(bool(x))'])
    if check.returncode:
        if not consent('Repair Python dependencies in .venv / Réparer les dépendances ?'):
            return 2
        subprocess.run([str(python), '-m', 'pip', 'install', '-r', str(ROOT / 'requirements.txt')], check=True)
        subprocess.run([str(python), '-c', 'from src.preflight import python_issues; import sys; sys.exit(bool(python_issues()))'], check=True)
    from src.pcap import find_tshark, list_interfaces
    if not find_tshark():
        print('Wireshark/TShark is missing. Packet tests require it. Other probes can run without capture.')
        if consent('Install/open official Wireshark installer / Installer Wireshark ?'):
            if os.name == 'nt' and shutil.which('winget'):
                subprocess.run(['winget', 'install', '--id', 'WiresharkFoundation.Wireshark', '--exact', '--source', 'winget', '--interactive'], check=True)
            elif sys.platform.startswith('linux') and shutil.which('apt-get'):
                prefix = [] if os.geteuid() == 0 else ['sudo']
                subprocess.run(prefix + ['apt-get', 'install', 'tshark'], check=True)
            else:
                print('Linux: install tshark with your package manager. macOS: install Wireshark and capture permissions.')
                webbrowser.open('https://www.wireshark.org/download.html')
            input('Complete installation, including TShark and Npcap on Windows, then press Enter. ')
    if not find_tshark() or not list_interfaces():
        print('Packet capture is unavailable. Check TShark, Npcap/libpcap and permissions. Capture requests will fail explicitly.')
        if os.name == 'nt' and find_tshark() and consent('Open the official Npcap installer page to install/repair capture support?'):
            webbrowser.open('https://npcap.com/#download')
            input('Complete Npcap installation, then press Enter. ')
            if not list_interfaces():
                print('Capture interfaces remain unavailable. Restart after driver installation or check permissions.')
    return subprocess.call([str(python), 'main.py', '--interactive'])


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError) as exc:
        print('Setup failed. No measurements started: ' + str(exc))
        raise SystemExit(2)
    except (KeyboardInterrupt, EOFError):
        print('\nSetup cancelled.')
        raise SystemExit(130)
