#!/bin/bash
# GistApp test runner
# Starts a test server, runs tests, stops it.

set -e
cd "$(dirname "$0")/.."

BASE=${TEST_BASE:-http://localhost:4000}

echo "🔍 Checking if server is running at $BASE..."

# Check if already running
if curl -s -o /dev/null -w "%{http_code}" "$BASE/api/me" 2>/dev/null | grep -q "401\|200"; then
  echo "✅ Server is running — using existing instance"
  SERVER_PID=""
else
  echo "🚀 Starting fresh server for tests..."
  pkill -9 node 2>/dev/null || true
  sleep 2
  node index.js > /tmp/gistapp-test-server.log 2>&1 &
  SERVER_PID=$!
  echo "   PID: $SERVER_PID"
  # Wait for ready
  for i in $(seq 1 20); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/me" 2>/dev/null || echo "000")
    if [ "$code" = "401" ] || [ "$code" = "200" ]; then
      echo "✅ Server ready after ${i}s"
      break
    fi
    sleep 1
  done
fi

echo ""
echo "🧪 Running tests..."
echo "================================================"
node --test tests/api.test.js 2>&1
EXIT_CODE=$?
echo "================================================"

if [ -n "$SERVER_PID" ]; then
  echo "🛑 Stopping test server (PID $SERVER_PID)"
  kill -9 "$SERVER_PID" 2>/dev/null || true
fi

if [ $EXIT_CODE -eq 0 ]; then
  echo "✅ All tests passed"
else
  echo "❌ Tests failed (exit code $EXIT_CODE)"
fi
exit $EXIT_CODE
