#!/bin/bash
echo "🔍 ANÁLISIS DE ATAQUES CAPTURADOS"
echo "================================="

echo "📁 Directory Traversal:"
tshark -r ../captures/sql-attack.pcap -Y "http.request.uri contains \"../\"" -T fields -e http.request.uri

echo -e "\n🚨 XSS Attacks:"
tshark -r ../captures/sql-attack.pcap -Y "http.request.uri contains \"script\"" -T fields -e http.request.uri

echo -e "\n💉 SQL Injection (POST data):"
tshark -r ../captures/sql-attack.pcap -Y "http.request.method == POST" -T fields -e http.file_data
