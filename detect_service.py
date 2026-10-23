#!/usr/bin/env python3

import time
import urllib.error
import urllib.request

from common import report_fault

SERVICE_URL = "http://10.0.0.2:8080/health"
CHECK_INTERVAL = 1
FAILURES_REQUIRED = 2

consecutive_failures = 0
fault_reported = False


def check_health():
    try:
        with urllib.request.urlopen(SERVICE_URL, timeout=2) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


if __name__ == "__main__":
    print(f"Monitoring service health at {SERVICE_URL}")

    while True:
        healthy = check_health()

        if healthy:
            consecutive_failures = 0

            if fault_reported:
                print("[HEALTHY] Service recovered")
                fault_reported = False
        else:
            consecutive_failures += 1

            if (
                consecutive_failures >= FAILURES_REQUIRED
                and not fault_reported
            ):
                report_fault(
                    "config_failure",
                    "h2:8080",
                    "Health check failed twice consecutively",
                )
                fault_reported = True

        time.sleep(CHECK_INTERVAL)
