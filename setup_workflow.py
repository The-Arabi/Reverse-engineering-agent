#!/usr/bin/env python3
"""
Setup Workflow for Reverse Engineering Research Agent Platform
Detects and assists with installation of required tools
"""

import os
import sys
import subprocess
import platform
import json
import shutil
from typing import Dict, List, Tuple, Optional
from pathlib import Path

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class SetupWorkflow:
    """Setup workflow for reverse engineering research platform"""

    def __init__(self):
        self.system = platform.system().lower()
        self.is_windows = self.system == 'windows'
        self.is_macos = self.system == 'darwin'
        self.is_linux = self.system == 'linux'

        self.tools_status = {}
        self.missing_tools = []
        self.optional_tools = []

        # Define required tools by category
        self.tool_categories = {
            'Disassemblers/Decompilers': [
                {'name': 'ghidra', 'check_cmd': ['ghidraRun', '--help'], 'install_hint': self._get_ghidra_install_hint()},
                {'name': 'radare2', 'check_cmd': ['r2', '-version'], 'install_hint': self._get_radare2_install_hint()},
                {'name': 'binary ninja', 'check_cmd': ['binaryninja', '--version'], 'install_hint': self._get_binary_ninja_install_hint()},
                # IDA Pro is commercial, so we just check if it's available
                {'name': 'ida pro', 'check_cmd': ['ida64', '--version'] if self.is_windows or self.is_linux else ['idaq64', '--version'], 'install_hint': 'Commercial tool - obtain from https://www.hex-rays.com/ida-pro/'},
            ],
            'Debuggers': [
                {'name': 'gdb', 'check_cmd': ['gdb', '--version'], 'install_hint': self._get_gdb_install_hint()},
                {'name': 'lldb', 'check_cmd': ['lldb', '--version'], 'install_hint': self._get_lldb_install_hint()},
                # WinDbg is Windows-specific
                {'name': 'windbg', 'check_cmd': ['windbg'], 'install_hint': 'Windows Debugging Tools - part of Windows SDK', 'platform': 'windows'},
            ],
            'Network Analysis': [
                {'name': 'wireshark', 'check_cmd': ['wireshark', '--version'], 'install_hint': self._get_wireshark_install_hint()},
                {'name': 'tcpdump', 'check_cmd': ['tcpdump', '--version'], 'install_hint': self._get_tcpdump_install_hint()},
            ],
            'Emulation/Virtualization': [
                {'name': 'qemu', 'check_cmd': ['qemu-system-x86_64', '--version'], 'install_hint': self._get_qemu_install_hint()},
                {'name': 'unicorn', 'check_cmd': None, 'install_hint': 'Python package: pip install unicorn', 'type': 'python_package'},
            ],
            'Firmware Analysis': [
                {'name': 'binwalk', 'check_cmd': ['binwalk', '--version'], 'install_hint': self._get_binwalk_install_hint()},
                {'name': 'firmware mod kit', 'check_cmd': ['fmkit', '--version'], 'install_hint': self._get_fmk_install_hint()},
            ],
            'Databases': [
                {'name': 'postgresql', 'check_cmd': ['psql', '--version'], 'install_hint': self._get_postgresql_install_hint()},
                {'name': 'neo4j', 'check_cmd': ['neo4j', 'version'], 'install_hint': self._get_neo4j_install_hint()},
                {'name': 'redis', 'check_cmd': ['redis-server', '--version'], 'install_hint': self._get_redis_install_hint()},
            ],
            'Development Tools': [
                {'name': 'node.js', 'check_cmd': ['node', '--version'], 'install_hint': self._get_nodejs_install_hint()},
                {'name': 'npm', 'check_cmd': ['npm', '--version'], 'install_hint': self._get_npm_install_hint()},
                {'name': 'python3', 'check_cmd': ['python3', '--version'], 'install_hint': 'Install Python 3.8+ from https://python.org'},
            ]
        }

    def _run_command(self, cmd: List[str], timeout: int = 10) -> Tuple[bool, str]:
        """Run a command and return success status and output"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except FileNotFoundError:
            return False, "Command not found"
        except Exception as e:
            return False, str(e)

    def _check_tool(self, tool_info: Dict) -> bool:
        """Check if a specific tool is available"""
        # Check platform compatibility
        if 'platform' in tool_info and tool_info['platform'] != self.system:
            return True  # Skip platform-incompatible tools

        # Handle Python packages specially
        if tool_info.get('type') == 'python_package':
            return self._check_python_package(tool_info['name'])

        # Handle tools without check commands (assume installed if mentioned)
        if not tool_info.get('check_cmd'):
            # For now, we'll assume these need manual installation
            return False

        success, output = self._run_command(tool_info['check_cmd'])
        return success

    def _check_python_package(self, package_name: str) -> bool:
        """Check if a Python package is installed"""
        try:
            __import__(package_name)
            return True
        except ImportError:
            return False

    def _get_ghidra_install_hint(self) -> str:
        if self.is_windows:
            return "Download from https://ghidra-sre.org/ and extract, or use Chocolatey: choco install ghidra"
        elif self.is_macos:
            return "Download from https://ghidra-sre.org/ and extract, or use brew: brew install ghidra"
        else:
            return "Download from https://ghidra-sre.org/ and extract, or use snap: snap install ghidra"

    def _get_radare2_install_hint(self) -> str:
        if self.is_windows:
            return "Use Chocolatey: choco install radare2"
        elif self.is_macos:
            return "Use brew: brew install radare2"
        else:
            return "Use apt: sudo apt install radare2, or pacman: sudo pacman -S radare2"

    def _get_binary_ninja_install_hint(self) -> str:
        return "Commercial tool - obtain from https://binary.ninja/"

    def _get_gdb_install_hint(self) -> str:
        if self.is_windows:
            return "Install via MSYS2: pacman -S mingw-w64-x86_64-gdb, or use Chocolatey: choco install gdb"
        elif self.is_macos:
            return "Use brew: brew install gdb (may require codesigning)"
        else:
            return "Use apt: sudo apt install gdb, or pacman: sudo pacman -S gdb"

    def _get_lldb_install_hint(self) -> str:
        if self.is_macos:
            return "Included with Xcode command line tools: xcode-select --install"
        else:
            return "Use apt: sudo apt install lldb, or pacman: sudo pacman -S lldb"

    def _get_wireshark_install_hint(self) -> str:
        if self.is_windows:
            return "Download from https://www.wireshark.org/, or use Chocolatey: choco install wireshark"
        elif self.is_macos:
            return "Use brew: brew install wireshark"
        else:
            return "Use apt: sudo apt install wireshark, or pacman: sudo pacman -S wireshark"

    def _get_tcpdump_install_hint(self) -> str:
        if self.is_windows:
            return "Install via WinPcap/Npcap: https://nmap.org/npcap/"
        elif self.is_macos:
            return "Use brew: brew install tcpdump"
        else:
            return "Use apt: sudo apt install tcpdump, or pacman: sudo pacman -S tcpdump"

    def _get_qemu_install_hint(self) -> str:
        if self.is_windows:
            return "Download from https://www.qemu.org/download/, or use Chocolatey: choco install qemu"
        elif self.is_macos:
            return "Use brew: brew install qemu"
        else:
            return "Use apt: sudo apt install qemu-system, or pacman: sudo pacman -S qemu"

    def _get_binwalk_install_hint(self) -> str:
        if self.is_windows:
            return "Use Chocolatey: choco install binwalk"
        elif self.is_macos:
            return "Use brew: brew install binwalk"
        else:
            return "Use apt: sudo apt install binwalk, or pacman: sudo pacman -S binwalk"

    def _get_fmk_install_hint(self) -> str:
        return "Clone from https://github.com/firmware-mod-kit/firmware-mod-kit and follow installation instructions"

    def _get_postgresql_install_hint(self) -> str:
        if self.is_windows:
            return "Download from https://www.postgresql.org/download/windows/, or use Chocolatey: choco install postgresql"
        elif self.is_macos:
            return "Use brew: brew install postgresql"
        else:
            return "Use apt: sudo apt install postgresql postgresql-contrib, or pacman: sudo pacman -S postgresql"

    def _get_neo4j_install_hint(self) -> str:
        if self.is_windows:
            return "Download from https://neo4j.com/download/, or use Chocolatey: choco install neo4j"
        elif self.is_macos:
            return "Use brew: brew install neo4j"
        else:
            return "Use apt: sudo apt install neo4j, or download from https://neo4j.com/download/"

    def _get_redis_install_hint(self) -> str:
        if self.is_windows:
            return "Use Chocolatey: choco install redis, or download from https://redis.io/download"
        elif self.is_macos:
            return "Use brew: brew install redis"
        else:
            return "Use apt: sudo apt install redis-server, or pacman: sudo pacman -S redis"

    def _get_nodejs_install_hint(self) -> str:
        if self.is_windows:
            return "Download from https://nodejs.org/, or use Chocolatey: choco install nodejs"
        elif self.is_macos:
            return "Use brew: brew install node"
        else:
            return "Use apt: sudo apt install nodejs npm, or pacman: sudo pacman -S nodejs npm"

    def _get_npm_install_hint(self) -> str:
        return "Installed with Node.js - see Node.js installation instructions above"

    def check_all_tools(self):
        """Check status of all tools"""
        print(f"{Colors.HEADER}{Colors.BOLD}Reverse Engineering Research Agent Platform - Setup Check{Colors.ENDC}")
        print(f"{Colors.OKBLUE}System: {platform.system()} {platform.release()}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}Python: {sys.version}{Colors.ENDC}")
        print("=" * 60)

        for category, tools in self.tool_categories.items():
            print(f"\n{Colors.HEADER}{category}:{Colors.ENDC}")
            print("-" * 40)

            for tool in tools:
                tool_name = tool['name']
                is_available = self._check_tool(tool)

                self.tools_status[tool_name] = {
                    'available': is_available,
                    'category': category,
                    'install_hint': tool.get('install_hint', 'Unknown'),
                    'optional': tool.get('optional', False)
                }

                status_color = Colors.OKGREEN if is_available else Colors.FAIL
                status_text = "✓ INSTALLED" if is_available else "✗ MISSING"
                print(f"{status_color}{status_text}{Colors.ENDC} {tool_name}")

                if not is_available and not tool.get('optional', False):
                    self.missing_tools.append({
                        'name': tool_name,
                        'category': category,
                        'hint': tool.get('install_hint', 'Please install manually')
                    })
                elif not is_available:
                    self.optional_tools.append({
                        'name': tool_name,
                        'category': category,
                        'hint': tool.get('install_hint', 'Please install manually')
                    })

    def print_summary(self):
        """Print setup summary"""
        print("\n" + "=" * 60)
        print(f"{Colors.HEADER}{Colors.BOLD}SETUP SUMMARY{Colors.ENDC}")
        print("=" * 60)

        total_checked = len(self.tools_status)
        total_installed = sum(1 for status in self.tools_status.values() if status['available'])

        print(f"Tools checked: {total_checked}")
        print(f"{Colors.OKGREEN}Installed: {total_installed}{Colors.ENDC}")
        print(f"{Colors.FAIL}Missing: {len(self.missing_tools)}{Colors.ENDC}")

        if self.missing_tools:
            print(f"\n{Colors.HEADER}{Colors.FAIL}MISSING REQUIRED TOOLS:{Colors.ENDC}")
            for tool in self.missing_tools:
                print(f"\n{Colors.FAIL}{tool['name']}{Colors.ENDC} ({tool['category']})")
                print(f"  {Colors.WARNING}How to install:{Colors.ENDC} {tool['hint']}")

        if self.optional_tools:
            print(f"\n{Colors.HEADER}{Colors.WARNING}OPTIONAL TOOLS (NOT INSTALLED):{Colors.ENDC}")
            for tool in self.optional_tools:
                print(f"\n{Colors.WARNING}{tool['name']}{Colors.ENDC} ({tool['category']})")
                print(f"  {Colors.OKBLUE}Suggestion:{Colors.ENDC} {tool['hint']}")

        # Check Python packages specifically for the project
        print(f"\n{Colors.HEADER}{Colors.BOLD}PROJECT DEPENDENCIES:{Colors.ENDC}")
        project_deps = [
            ('flask', 'Web dashboard backend'),
            ('flask-cors', 'CORS support for Flask'),
            ('psycopg2-binary', 'PostgreSQL adapter for Python'),
            ('neo4j', 'Neo4j driver for Python'),
            ('redis', 'Redis client for Python'),
        ]

        for package, description in project_deps:
            try:
                __import__(package.replace('-', '_'))
                print(f"{Colors.OKGREEN}✓{Colors.ENDC} {package} - {description}")
            except ImportError:
                print(f"{Colors.FAIL}✗{Colors.ENDC} {package} - {description} (install with: pip install {package})")

        print(f"\n{Colors.HEADER}{Colors.BOLD}NEXT STEPS:{Colors.ENDC}")
        if self.missing_tools:
            print(f"1. {Colors.FAIL}Install missing required tools{Colors.ENDC} using the hints above")
            print("2. Install project Python dependencies: pip install -r requirements.txt")
            print("3. Set up environment variables for database connections")
            print("4. Run the platform: python web_dashboard.py")
        else:
            print(f"1. {Colors.OKGREEN}All required tools are installed!{Colors.ENDC}")
            print("2. Install project Python dependencies: pip install -r requirements.txt")
            print("3. Set up environment variables for database connections")
            print("4. Run the platform: python web_dashboard.py")

        print(f"\n{Colors.HEADER}For detailed documentation, see README.md{Colors.ENDC}")

    def generate_requirements_txt(self):
        """Generate requirements.txt file for Python dependencies"""
        requirements = [
            "Flask>=2.3.0",
            "Flask-CORS>=4.0.0",
            "psycopg2-binary>=2.9.0",
            "neo4j>=5.0.0",
            "redis>=4.5.0",
        ]

        with open('requirements.txt', 'w') as f:
            f.write('\n'.join(requirements))

        print(f"{Colors.OKGREEN}Generated requirements.txt{Colors.ENDC}")

    def create_env_template(self):
        """Create a template .env file for environment variables"""
        env_template = '''# Environment Variables for Reverse Engineering Research Agent Platform
# Copy this file to .env and fill in the values

# PostgreSQL Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=knowledge_base
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_postgres_password_here

# Neo4j Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_neo4j_password_here

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password_here
REDIS_DB=0

# Dashboard Configuration
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=5000
DASHBOARD_DEBUG=False
'''

        with open('.env.template', 'w') as f:
            f.write(env_template)

        print(f"{Colors.OKGREEN}Generated .env.template{Colors.ENDC}")


def main():
    """Main function to run the setup workflow"""
    workflow = SetupWorkflow()

    # Check all tools
    workflow.check_all_tools()

    # Print summary
    workflow.print_summary()

    # Generate helper files
    workflow.generate_requirements_txt()
    workflow.create_env_template()

    # Return appropriate exit code
    if workflow.missing_tools:
        print(f"\n{Colors.WARNING}Warning: Some required tools are missing. Please install them before proceeding.{Colors.ENDC}")
        return 1
    else:
        print(f"\n{Colors.OKGREEN}Success: All required tools are installed!{Colors.ENDC}")
        return 0


if __name__ == "__main__":
    sys.exit(main())