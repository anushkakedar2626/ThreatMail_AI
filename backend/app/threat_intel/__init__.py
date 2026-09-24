import os

_HAS_ANY_REAL_KEY = any([
    os.getenv("IPINFO_TOKEN"),
    os.getenv("ABUSEIPDB_KEY"),
    os.getenv("VIRUSTOTAL_KEY"),
])

if _HAS_ANY_REAL_KEY:
    from . import real_provider as provider
else:
    from . import mock_provider as provider

__all__ = ["provider"]
