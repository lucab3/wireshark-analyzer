#!/usr/bin/env python3
import subprocess
import json
import re
from pathlib import Path

class WiresharkAnalyzer:
    def __init__(self, captures_dir="../captures"):
        self.captures_dir = Path(captures_dir)
        self.findings = []

    def analyze_sql_injection(self, pcap_file):
        """Buscar patrones de SQL injection en tráfico HTTP"""
        print(f"🔍 Analizando SQL injection en {pcap_file}...")
        
        # Usar tshark para extraer payloads HTTP
        cmd = [
            'tshark', '-r', str(pcap_file),
            '-Y', 'http.request',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'http.request.uri',
            '-e', 'http.request.method'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            sql_patterns = [
                r"union\s+select",
                r"'\s+or\s+'1'\s*=\s*'1",
                r"drop\s+table",
                r";\s*--",
                r"'\s+union\s+"
            ]
            
            findings = []
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        ip, uri, method = parts[0], parts[1], parts[2]
                        
                        for pattern in sql_patterns:
                            if re.search(pattern, uri, re.IGNORECASE):
                                findings.append({
                                    'type': 'SQL Injection',
                                    'source_ip': ip,
                                    'payload': uri,
                                    'method': method,
                                    'severity': 'HIGH'
                                })
            
            return findings
                        
        except Exception as e:
            print(f"Error analyzing {pcap_file}: {e}")
            return []

    def analyze_port_scan(self, pcap_file):
        """Detectar port scanning"""
        print(f"🔍 Analizando port scan en {pcap_file}...")
        
        cmd = [
            'tshark', '-r', str(pcap_file),
            '-Y', 'tcp.flags.syn==1 and tcp.flags.ack==0',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'ip.dst', 
            '-e', 'tcp.dstport'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Contar puertos por IP origen
            scan_data = {}
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        src_ip, dst_ip, port = parts[0], parts[1], parts[2]
                        
                        key = f"{src_ip}->{dst_ip}"
                        if key not in scan_data:
                            scan_data[key] = set()
                        scan_data[key].add(port)
            
            findings = []
            for connection, ports in scan_data.items():
                if len(ports) > 5:  # Más de 5 puertos = posible scan
                    src, dst = connection.split('->')
                    findings.append({
                        'type': 'Port Scan',
                        'source_ip': src,
                        'target_ip': dst,
                        'ports_scanned': len(ports),
                        'ports': list(ports),
                        'severity': 'MEDIUM'
                    })
            
            return findings
            
        except Exception as e:
            print(f"Error analyzing port scan: {e}")
            return []

    def analyze_brute_force(self, pcap_file):
        """Detectar brute force SSH"""
        print(f"🔍 Analizando brute force en {pcap_file}...")
        
        cmd = [
            'tshark', '-r', str(pcap_file),
            '-Y', 'tcp.dstport==22',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.flags'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Contar intentos de conexión SSH por IP
            connection_attempts = {}
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        src_ip, dst_ip = parts[0], parts[1]
                        
                        key = f"{src_ip}->{dst_ip}"
                        connection_attempts[key] = connection_attempts.get(key, 0) + 1
            
            findings = []
            for connection, attempts in connection_attempts.items():
                if attempts > 5:  # Más de 5 intentos = posible brute force
                    src, dst = connection.split('->')
                    findings.append({
                        'type': 'SSH Brute Force',
                        'source_ip': src,
                        'target_ip': dst,
                        'attempts': attempts,
                        'severity': 'HIGH'
                    })
            
            return findings
            
        except Exception as e:
            print(f"Error analyzing brute force: {e}")
            return []

    def analyze_all_captures(self):
        """Analizar todas las capturas disponibles"""
        all_findings = []
        
        pcap_files = list(self.captures_dir.glob("*.pcap"))
        
        for pcap_file in pcap_files:
            print(f"\n📁 Analizando {pcap_file.name}...")
            
            if "sql-injection" in pcap_file.name:
                findings = self.analyze_sql_injection(pcap_file)
                all_findings.extend(findings)
            
            elif "port-scan" in pcap_file.name:
                findings = self.analyze_port_scan(pcap_file)
                all_findings.extend(findings)
            
            elif "brute-force" in pcap_file.name:
                findings = self.analyze_brute_force(pcap_file)
                all_findings.extend(findings)
        
        return all_findings

    def generate_report(self, findings):
        """Generar reporte de hallazgos"""
        report = "# 🛡️ Reporte de Análisis de Tráfico de Red\n\n"
        report += f"**Fecha:** {subprocess.run(['date'], capture_output=True, text=True).stdout.strip()}\n"
        report += f"**Total de hallazgos:** {len(findings)}\n\n"
        
        # Agrupar por tipo de ataque
        attack_types = {}
        for finding in findings:
            attack_type = finding['type']
            if attack_type not in attack_types:
                attack_types[attack_type] = []
            attack_types[attack_type].append(finding)
        
        for attack_type, attacks in attack_types.items():
            report += f"## {attack_type}\n\n"
            
            for i, attack in enumerate(attacks, 1):
                report += f"### Hallazgo #{i}\n"
                report += f"- **Severidad:** {attack['severity']}\n"
                report += f"- **IP Origen:** `{attack['source_ip']}`\n"
                
                if 'payload' in attack:
                    report += f"- **Payload:** `{attack['payload']}`\n"
                if 'target_ip' in attack:
                    report += f"- **IP Destino:** `{attack['target_ip']}`\n"
                if 'ports_scanned' in attack:
                    report += f"- **Puertos escaneados:** {attack['ports_scanned']}\n"
                if 'attempts' in attack:
                    report += f"- **Intentos:** {attack['attempts']}\n"
                
                report += "\n"
        
        # Guardar reporte
        report_file = Path("../analysis/findings-report.md")
        report_file.parent.mkdir(exist_ok=True)
        report_file.write_text(report)
        
        print(f"📊 Reporte guardado en: {report_file}")
        return report

def main():
    analyzer = WiresharkAnalyzer()
    
    print("🚀 Iniciando análisis automatizado...")
    findings = analyzer.analyze_all_captures()
    
    print(f"\n✅ Análisis completado. {len(findings)} hallazgos detectados.")
    
    if findings:
        report = analyzer.generate_report(findings)
        print("\n" + "="*50)
        print(report)
    else:
        print("ℹ️  No se detectaron amenazas en las capturas analizadas.")

if __name__ == "__main__":
    main()
