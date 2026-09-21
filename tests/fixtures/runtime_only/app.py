import os

PLUGIN = os.getenv("PLUGIN_NAME", "default")
try:
    mod = __import__(PLUGIN)
except ImportError:
    mod = None
