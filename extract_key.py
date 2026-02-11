import re

# Read raw log bytes
with open(r'd:\ZKS Protocol_Research\ZKS Protocol\server_vps.log', 'rb') as f:
    data = f.read()

# Strip ANSI escape codes
clean = re.sub(rb'\x1b\[[0-9;]*m', b'', data).decode('utf-8', errors='ignore')

# Extract key after "VK): "
m = re.search(r'VK\): ([A-Za-z0-9+/=]+)', clean)
if m:
    key = m.group(1)
    print(f"Key length: {len(key)}")
    print(f"First 80 chars: {key[:80]}")
    print(f"Last 20 chars: {key[-20:]}")
    with open(r'd:\ZKS Protocol_Research\ZKS Protocol\server_key.txt', 'w', newline='') as f:
        f.write(key)
    print("Key saved to server_key.txt")
else:
    print("ERROR: Key not found in log!")
    # Try to find what's around "VK"
    idx = clean.find("VK)")
    if idx >= 0:
        print(f"Found 'VK)' at index {idx}")
        print(f"Context: ...{repr(clean[idx:idx+100])}...")
