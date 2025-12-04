bind = "127.0.0.1:5000"
workers = 2
worker_class = "sync"
worker_connections = 1000
timeout = 120
keepalive = 5

# Logging
accesslog = "/root/captive-portal/logs/access.log"
errorlog = "/root/captive-portal/logs/error.log"
loglevel = "debug"  # Change to debug for troubleshooting

# Process naming
proc_name = "captive-portal"

# Server mechanics
preload_app = False  # Set to False for debugging
max_requests = 1000
max_requests_jitter = 100

# For debugging
capture_output = True
enable_stdio_inheritance = True
