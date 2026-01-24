!# /bin/bash
# Checks for any potential reverse shells

echo " Checking for suspicious reverse shell activity..."
echo "-----------------------------------------------"

SUSPICIOUS=false


# Checking for suspicious outbound connections
echo "[*] Checking active network connections..."
CONNECTIONS=$(ss -tunap 2>/dev/null | grep -E "bash|sh|nc|python|perl|php")

if [[ -n "$CONNECTIONS" ]]; then
    echo "[!] Suspicious network connections found:"
    echo "$CONNECTIONS"
    SUSPICIOUS=true
fi


# Checking for common reverse shell command
echo "[*] Checking running processes..."
PROCESSES=$(ps aux | grep -E "bash -i|/dev/tcp|nc -e|python -c|perl -e|php -r" | grep -v grep)

if [[ -n "$PROCESSES" ]]; then
    echo "[!] Suspicious processes detected:"
    echo "$PROCESSES"
    SUSPICIOUS=true
fi


# Checking for listening shells on uncommon ports
echo "[*] Checking listening ports..."
LISTENERS=$(ss -tulnp | grep -E "bash|sh|nc|python|perl|php")

if [[ -n "$LISTENERS" ]]; then
    echo "[!] Suspicious listeners found:"
    echo "$LISTENERS"
    SUSPICIOUS=true
fi


echo "-----------------------------------------------"

# Final verdict
if [ "$SUSPICIOUS" = true ]; then
    echo "UH OH something doesn't look right"
else
    echo "No obvious reverse shell activity detected."
fi