#!/bin/bash

echo "🔥 Generando tráfico malicioso para análisis..."

# Crear directorio de capturas
mkdir -p ../captures

# 1. Capturar tráfico normal (30 segundos)
echo "📊 Capturando tráfico normal..."
sudo tcpdump -i any -w ../captures/normal-traffic.pcap -c 50 &
TCPDUMP_PID=$!

# Generar tráfico normal
curl -s http://httpbin.org/get > /dev/null
curl -s http://httpbin.org/post -d "data=test" > /dev/null
nslookup google.com > /dev/null
ping -c 3 8.8.8.8 > /dev/null

sleep 5
sudo kill $TCPDUMP_PID 2>/dev/null

# 2. Simular SQL Injection
echo "💉 Simulando SQL Injection..."
sudo tcpdump -i any -w ../captures/sql-injection.pcap -c 30 &
TCPDUMP_PID=$!

# Requests con SQL injection
curl -s "http://httpbin.org/get?id=1' UNION SELECT * FROM users--" > /dev/null
curl -s "http://httpbin.org/get?user=admin' OR '1'='1" > /dev/null
curl -s "http://httpbin.org/post" -d "username=admin'; DROP TABLE users;--" > /dev/null

sleep 3
sudo kill $TCPDUMP_PID 2>/dev/null

# 3. Simular Port Scanning
echo "🔍 Simulando Port Scan..."
sudo tcpdump -i any -w ../captures/port-scan.pcap -c 50 &
TCPDUMP_PID=$!

# Port scan manual con hping3
for port in 22 23 25 53 80 110 143 443; do
    hping3 -S -p $port -c 1 8.8.8.8 > /dev/null 2>&1
done

sleep 5
sudo kill $TCPDUMP_PID 2>/dev/null

echo "✅ Capturas completadas en ../captures/"
echo "📂 Archivos generados:"
ls -la ../captures/
