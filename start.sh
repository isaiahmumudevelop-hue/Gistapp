#!/data/data/com.termux/files/usr/bin/bash
cd ~/gistapp
pkill -f "node index.js" 2>/dev/null
sleep 1
echo "Starting server..."
node index.js
