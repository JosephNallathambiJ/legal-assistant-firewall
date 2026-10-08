"""Application-Layer Rate Limiting Tests for HNX26EPS01 Gateway."""

import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from gateway_proxy import TokenBucketRateLimiter


def test_token_bucket_burst_and_throttling():
    # 5 requests per second, burst 10
    limiter = TokenBucketRateLimiter(rate=5.0, burst=10)
    client_ip = "192.168.1.100"

    # Consume all burst tokens (10)
    for _ in range(10):
        assert limiter.allow(client_ip) is True

    # 11th request immediately must be throttled
    assert limiter.allow(client_ip) is False
    assert limiter.total_accepted == 10
    assert limiter.total_throttled == 1

    # Wait 0.3 seconds -> refills ~1.5 tokens
    time.sleep(0.3)
    assert limiter.allow(client_ip) is True
    assert limiter.total_accepted == 11


def test_per_client_isolation():
    limiter = TokenBucketRateLimiter(rate=2.0, burst=2)
    client_a = "10.0.0.1"
    client_b = "10.0.0.2"

    # Exhaust Client A
    assert limiter.allow(client_a) is True
    assert limiter.allow(client_a) is True
    assert limiter.allow(client_a) is False

    # Client B still has its full burst available
    assert limiter.allow(client_b) is True
    assert limiter.allow(client_b) is True
    assert limiter.allow(client_b) is False
