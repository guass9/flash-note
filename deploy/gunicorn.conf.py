import multiprocessing
import os


bind = os.getenv("GUNICORN_BIND", "0.0.0.0:5000")
workers = int(os.getenv("GUNICORN_WORKERS", max(2, multiprocessing.cpu_count() // 2)))
threads = int(os.getenv("GUNICORN_THREADS", "2"))
timeout = int(os.getenv("GUNICORN_TIMEOUT", "60"))
graceful_timeout = int(os.getenv("GUNICORN_GRACEFUL_TIMEOUT", "30"))
keepalive = int(os.getenv("GUNICORN_KEEPALIVE", "5"))
worker_class = os.getenv("GUNICORN_WORKER_CLASS", "gthread")

# Keep access/error logs in the existing backend log location for minimal migration.
accesslog = os.getenv("GUNICORN_ACCESS_LOG", "/root/flash-note/backend/app.log")
errorlog = os.getenv("GUNICORN_ERROR_LOG", "/root/flash-note/backend/app.log")
loglevel = os.getenv(
    "GUNICORN_LOG_LEVEL",
    os.getenv("APP_LOG_LEVEL", "info")
).lower()
capture_output = True
access_log_format = (
    '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s '
    '"%(f)s" "%(a)s" %(D)sus'
)

# Ensure app import path remains stable regardless of caller cwd.
chdir = "/root/flash-note/backend"
