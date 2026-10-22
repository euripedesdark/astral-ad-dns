#!/usr/bin/env python3

import subprocess
import os
import sys
import time
import csv
from typing import List, Tuple, Dict


class VLANConfigurator:
    def __init__(self):
        self.trunk_interface = "ens224"
        self.vlans = [
            ("10", "br-vlan10", "192.168.10.1/24"),
            ("2", "br-vlan2", "192.168.2.1/24"),
            ("20", "br-vlan20", "192.168.20.1/24"),
            ("30", "br-vlan30", "192.168.30.1/24"),
        ]
        self.selected_dns_servers = []  # Será preenchido interativamente

    def run_command(self, cmd, shell=False, check=True):
        """Executa um comando e retorna o resultado"""
        try:
            if shell:
                result = subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)
            else:
                result = subprocess.run(cmd, check=check, capture_output=True, text=True)
            return result
        except subprocess.CalledProcessError as e:
            print(f"Erro ao executar comando: {cmd}")
            print(f"Erro: {e}")
            if check:
                raise
            return e

    # =============== DNS SELECTION LOGIC ===============
    def load_dns_from_csv(self) -> List[Dict]:
        dns_list = []
        try:
            with open('nameservers.csv', 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['dnssec'] == 'true' and row['reliability'] and float(row['reliability']) >= 0.95:
                        dns_list.append(row)
        except FileNotFoundError:
            print("❌ Arquivo 'nameservers.csv' não encontrado!")
            sys.exit(1)
        return dns_list

    def group_dns_by_cloud_and_country(self, dns_list: List[Dict]) -> Dict[str, Dict[str, List[Dict]]]:
        grouped = {}
        for entry in dns_list:
            cloud = entry['as_org']
            country = entry['country_code']
            if cloud not in grouped:
                grouped[cloud] = {}
            if country not in grouped[cloud]:
                grouped[cloud][country] = []
            grouped[cloud][country].append(entry)
        return grouped

    def select_dns_interactive(self):
        dns_list = self.load_dns_from_csv()
        grouped = self.group_dns_by_cloud_and_country(dns_list)

        print("\n🌐 Escolha servidores DNS (até 3):")
        print("=" * 60)

        selected = []
        all_options = []

        # Mostra opções numeradas
        idx = 1
        for cloud, countries in grouped.items():
            print(f"\n☁️  {cloud}")
            for country, servers in countries.items():
                print(f"  🌍 {country}")
                for server in servers[:3]:  # limite para não sobrecarregar
                    print(f"    {idx}. {server['ip_address']} ({server['version'] or 'N/A'})")
                    all_options.append(server['ip_address'])
                    idx += 1

        print(f"\nDigite até 3 números separados por vírgula (ex: 1,5,12):")
        try:
            choices = input("> ").strip().split(',')
            for c in choices:
                i = int(c.strip()) - 1
                if 0 <= i < len(all_options):
                    selected.append(all_options[i])
        except (ValueError, IndexError):
            print("⚠️  Escolha inválida. Usando fallback.")
            selected = ["1.1.1.1", "8.8.8.8"]

        self.selected_dns_servers = selected[:3] or ["1.1.1.1", "8.8.8.8"]
        print(f"\n✅ DNS selecionados: {self.selected_dns_servers}")

    # =============== PI-HOLE & NETWORK CONFIG ===============
    def stop_pihole(self):
        print("⏹️  Parando Pi-hole...")
        self.run_command(["sudo", "systemctl", "stop", "pihole-FTL"], check=False)

    def cleanup_vlan_connections(self):
        print("🧹 Limpando conexões de VLANs existentes...")
        result = self.run_command(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show"])
        for line in result.stdout.split('\n'):
            if line and any(x in line for x in ['vlan', 'br-vlan']):
                connection_name = line.split(':')[0]
                print(f"  Removendo: {connection_name}")
                self.run_command(["sudo", "nmcli", "connection", "delete", connection_name], check=False)

    def configure_trunk(self):
        print(f"🔧 Configurando trunk {self.trunk_interface}...")
        result = self.run_command(["nmcli", "connection", "show"], check=False)
        if f"{self.trunk_interface}-trunk" not in result.stdout:
            self.run_command([
                "sudo", "nmcli", "connection", "add", "type", "ethernet",
                "ifname", self.trunk_interface, "con-name", f"{self.trunk_interface}-trunk",
                "ipv4.method", "disabled", "ipv6.method", "disabled"
            ])
            print(f"  ✅ Trunk {self.trunk_interface} criado")
        else:
            print(f"  ⚠️  Trunk {self.trunk_interface} já existe")

    def create_vlans(self):
        print("🏗️  Criando bridges e VLANs...")
        for vlan_id, bridge_name, ip_cidr in self.vlans:
            print(f"  🔧 Criando VLAN {vlan_id} - {bridge_name}...")

            # Bridge
            self.run_command([
                "sudo", "nmcli", "connection", "add", "type", "bridge",
                "ifname", bridge_name, "con-name", f"bridge-vlan{vlan_id}",
                "ipv4.addresses", ip_cidr, "ipv4.method", "manual",
                "ipv6.method", "disabled", "bridge.stp", "no"
            ])

            # VLAN slave
            self.run_command([
                "sudo", "nmcli", "connection", "add", "type", "vlan",
                "con-name", f"vlan{vlan_id}", "dev", self.trunk_interface,
                "id", vlan_id, "master", bridge_name, "slave-type", "bridge"
            ])
            print(f"  ✅ VLAN {vlan_id} configurada")

    def configure_pihole_toml(self):
        print("⚙️  Configurando pihole.toml...")
        self.run_command(["sudo", "cp", "/etc/pihole/pihole.toml", "/etc/pihole/pihole.toml.backup"])

        upstreams = '", "'.join(self.selected_dns_servers)
        toml_content = f"""# Pi-hole configuration file
# Generated by VLAN setup script

[dns]
interface = "br-lan"
listeningMode = "ALL"
upstreams = ["{upstreams}"]

[misc]
etc_dnsmasq_d = true

[dhcp]
active = true
start = "192.168.0.100"
end = "192.168.0.200"
router = "192.168.0.1"
leaseTime = "24h"
domain = "lan"
"""
        self.run_command(f'echo "{toml_content}" | sudo tee /etc/pihole/pihole.toml > /dev/null', shell=True)
        print("  ✅ pihole.toml configurado")

    def create_dnsmasq_configs(self):
        print("📝 Criando configurações dnsmasq para VLANs...")
        dns_str = ", ".join(self.selected_dns_servers)
        configs = {
            "10-vlan10.conf": f"""interface=br-vlan10
bind-interfaces
dhcp-range=192.168.10.100,192.168.10.200,255.255.255.0,24h
dhcp-option=3,192.168.10.1
dhcp-option=6,{dns_str}
""",
            "20-vlan2.conf": f"""interface=br-vlan2
bind-interfaces
dhcp-range=192.168.2.100,192.168.2.200,255.255.255.0,24h
dhcp-option=3,192.168.2.1
dhcp-option=6,{dns_str}
""",
            "30-vlan20.conf": f"""interface=br-vlan20
bind-interfaces
dhcp-range=192.168.20.100,192.168.20.200,255.255.255.0,24h
dhcp-option=3,192.168.20.1
dhcp-option=6,{dns_str}
""",
            "40-vlan30.conf": f"""interface=br-vlan30
bind-interfaces
dhcp-range=192.168.30.100,192.168.30.200,255.255.255.0,24h
dhcp-option=3,192.168.30.1
dhcp-option=6,{dns_str}
"""
        }

        for filename, content in configs.items():
            filepath = f"/etc/dnsmasq.d/{filename}"
            self.run_command(f'echo "{content}" | sudo tee {filepath} > /dev/null', shell=True)
            print(f"  ✅ {filename} criado")

    def configure_iptables(self):
        print("🛡️  Configurando iptables...")
        interfaces = ["br-lan", "br-vlan10", "br-vlan2", "br-vlan20", "br-vlan30"]
        for interface in interfaces:
            # DNS UDP/TCP
            self.run_command(
                ["sudo", "iptables", "-A", "INPUT", "-i", interface, "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                check=False)
            self.run_command(
                ["sudo", "iptables", "-A", "INPUT", "-i", interface, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
                check=False)
            # DHCP
            self.run_command(
                ["sudo", "iptables", "-A", "INPUT", "-i", interface, "-p", "udp", "--dport", "67", "-j", "ACCEPT"],
                check=False)
            print(f"  ✅ Regras iptables para {interface}")
        print("  ✅ iptables configurado para DNS e DHCP")

    def activate_connections(self):
        print("🔌 Ativando conexões...")
        self.run_command(["sudo", "nmcli", "connection", "up", f"{self.trunk_interface}-trunk"], check=False)
        for vlan_id, bridge_name, _ in self.vlans:
            self.run_command(["sudo", "nmcli", "connection", "up", f"bridge-vlan{vlan_id}"])
            self.run_command(["sudo", "nmcli", "connection", "up", f"vlan{vlan_id}"])
        print("  ✅ Conexões ativadas")

    def restart_pihole(self):
        print("🔄 Reiniciando Pi-hole...")
        self.run_command(["sudo", "systemctl", "restart", "pihole-FTL"])
        time.sleep(3)
        print("  ✅ Pi-hole reiniciado")

    def verify_configuration(self):
        print("\n" + "=" * 50)
        print("✅ VERIFICAÇÃO FINAL")
        print("=" * 50)

        checks = [
            ("1. Interfaces de rede:", "ip addr show | grep -E '(br-|vlan)' | grep -E 'inet|UP'"),
            ("2. Conexões NetworkManager:", "nmcli connection show | grep -E '(bridge|vlan)'"),
            ("3. Arquivos dnsmasq.d:", "ls -la /etc/dnsmasq.d/"),
            ("4. Configuração pihole.toml:", "grep -E 'upstreams' /etc/pihole/pihole.toml"),
            ("5. Status Pi-hole:", "systemctl is-active pihole-FTL"),
            ("6. Porta 53:", "ss -tuln | grep ':53'"),
            ("7. Regras iptables:", "iptables -L INPUT -n | grep -E ':(53|67)'"),
        ]

        for label, cmd in checks:
            print(f"\n{label}")
            self.run_command(cmd, shell=True, check=False)

    def run(self):
        try:
            print("🚀 INICIANDO CONFIGURAÇÃO DE VLANS + PI-HOLE + FIREWALL DNS")
            print("=" * 60)

            # Etapa 1: Seleção de DNS
            self.select_dns_interactive()

            # Etapa 2: Configuração de rede
            steps = [
                self.stop_pihole,
                self.cleanup_vlan_connections,
                self.configure_trunk,
                self.create_vlans,
                self.configure_pihole_toml,
                self.create_dnsmasq_configs,
                self.configure_iptables,
                self.activate_connections,
                self.restart_pihole,
                self.verify_configuration
            ]

            for step in steps:
                step()

            print("\n" + "=" * 50)
            print("🎉 CONFIGURAÇÃO CONCLUÍDA COM SUCESSO!")
            print("=" * 50)
            print("\n📌 RESUMO DA CONFIGURAÇÃO:")
            print(f"  • LAN: 192.168.0.1/24 (via pihole.toml)")
            for vlan_id, _, ip_cidr in self.vlans:
                print(f"  • VLAN{vlan_id}: {ip_cidr} (via dnsmasq.d)")
            print(f"  • DNS upstream: {', '.join(self.selected_dns_servers)}")
            print("  • iptables configurado para DNS (53) e DHCP (67)")
            print("  • Pi-hole ouvindo em todas as interfaces")
            print("\n✅ Pronto para uso!")

        except Exception as e:
            print(f"\n❌ ERRO durante a configuração: {e}")
            sys.exit(1)


def main():
    if os.geteuid() != 0:
        print("❌ Este script precisa ser executado como root/sudo")
        sys.exit(1)

    configurator = VLANConfigurator()
    configurator.run()


if __name__ == "__main__":
    main()