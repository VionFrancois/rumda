#!/bin/sh

# Pull quark rules every 24 hours
echo "0 0 * * * cd /server/quark-rules && git pull" | crontab -
cron

# Start the python server
exec uvicorn server:app \
  --host 0.0.0.0 \
  --port 8000
  --workers 2