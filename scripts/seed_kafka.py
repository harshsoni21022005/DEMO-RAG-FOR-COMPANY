"""
scripts/seed_kafka.py

Seed script — sends 100 realistic fake XDR events to the Kafka topic.

Events vary across:
  - Hosts: PC-101 to PC-110
  - Event types: Malware, Phishing, Scan, Exfil, Ransomware, LateralMovement
  - Severities: high, medium, low
  - Realistic signatures (Suricata/Snort style)
  - Random source/destination IPs
  - Timestamps spread over the last 2 hours
  - Optional security fields (mitre_technique, process_name, username, etc.)

Usage:
    python scripts/seed_kafka.py
    python scripts/seed_kafka.py --count 200 --topic xdr.events
"""

import argparse
import json
import logging
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from dotenv import load_dotenv
from kafka import KafkaProducer
from kafka.errors import KafkaError

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] seed_kafka — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC: str = os.getenv("KAFKA_TOPIC", "xdr.events")

# ---------------------------------------------------------------------------
# Fake data definitions
# ---------------------------------------------------------------------------
HOSTS = [f"PC-{i:03d}" for i in range(101, 111)]  # PC-101 … PC-110

EVENT_TYPES = ["Malware", "Phishing", "Scan", "Exfil", "Ransomware", "LateralMovement"]

SEVERITIES = ["high", "medium", "low"]
SEVERITY_WEIGHTS = [0.25, 0.45, 0.30]

SIGNATURES = {
    "Malware": [
        "ET MALWARE CnC Beacon",
        "ET MALWARE Trojan Downloader",
        "ET MALWARE Cobalt Strike Beacon",
        "ET MALWARE AgentTesla Keylogger",
        "ET MALWARE Emotet Binary Download",
        "ET MALWARE QakBot CnC Activity",
        "ET MALWARE Trickbot Payload",
        "ET MALWARE RedLine Stealer",
        "ET MALWARE AsyncRAT Activity",
        "ET MALWARE DarkComet RAT",
    ],
    "Phishing": [
        "ET PHISHING Credential Harvest Landing Page",
        "ET PHISHING Microsoft O365 Spearphish",
        "ET PHISHING DocuSign Lure",
        "ET PHISHING PDF Malware Delivery",
        "ET PHISHING HTML Attachment with JS",
        "ET PHISHING AiTM Session Token Theft",
        "ET PHISHING HTML Form Credential Harvest",
    ],
    "Scan": [
        "ET SCAN Nmap Scripting Engine UA",
        "ET SCAN Masscan Detection",
        "ET SCAN SYN Scan Detected",
        "ET SCAN Port Sweep Detected",
        "ET SCAN SSH Brute Force Attempt",
        "ET SCAN RDP Scan",
        "ET SCAN SMB Scanning Activity",
        "ET SCAN FTP Brute Force",
    ],
    "Exfil": [
        "ET EXFIL DNS Tunneling - Iodine",
        "ET EXFIL HTTP POST Large Upload",
        "ET EXFIL Pastebin Data Upload",
        "ET EXFIL Google Drive Large Upload",
        "ET EXFIL FTP Data Channel Detected",
        "ET EXFIL ICMP Tunneling",
        "ET EXFIL Discord Webhook Abuse",
    ],
    "Ransomware": [
        "ET RANSOMWARE LockBit 3.0 Ransom Note",
        "ET RANSOMWARE BlackCat Encryption Activity",
        "ET RANSOMWARE Conti Beacon",
        "ET RANSOMWARE ALPHV Payment Site",
        "ET RANSOMWARE Clop Dropper",
        "ET RANSOMWARE REvil Beacon",
    ],
    "LateralMovement": [
        "ET POLICY SMB2 NT Create AndX File",
        "ET POLICY PsExec Service Installation",
        "ET POLICY WMI Remote Execution",
        "ET POLICY Pass-the-Hash Authentication",
        "ET POLICY Kerberoasting Activity",
        "ET POLICY BloodHound LDAP Query",
        "ET POLICY DCSync Replication Request",
    ],
}

MITRE_TECHNIQUES = {
    "Malware": ["T1055", "T1027", "T1071.001", "T1105", "T1486"],
    "Phishing": ["T1566.001", "T1566.002", "T1598", "T1539"],
    "Scan": ["T1046", "T1595.001", "T1595.002", "T1590"],
    "Exfil": ["T1041", "T1567", "T1048.003", "T1048"],
    "Ransomware": ["T1486", "T1490", "T1485", "T1489"],
    "LateralMovement": ["T1021.001", "T1021.002", "T1550.002", "T1558.003", "T1106"],
}

PROCESS_NAMES = [
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "regsvr32.exe", "mshta.exe", "rundll32.exe", "svchost.exe",
    "lsass.exe", "explorer.exe", "python.exe", "msiexec.exe",
    "certutil.exe", "bitsadmin.exe", "wmic.exe",
]

USERNAMES = [
    "jsmith", "admin", "SYSTEM", "adm.service", "backup_user",
    "svc_backup", "helpdesk", "dbadmin", "domain\\jdoe", "NT AUTHORITY\\SYSTEM",
]

CONTAINER_NAMES = [
    "nginx", "redis", "postgres", "webapp-api", "auth-service",
    "payment-svc", "worker-job", "data-pipeline",
]


def _random_private_ip() -> str:
    """Generate a random RFC1918 IP address."""
    prefix = random.choice(["192.168", "10.0", "172.16", "10.10"])
    return f"{prefix}.{random.randint(0, 254)}.{random.randint(1, 254)}"


def _random_public_ip() -> str:
    """Generate a random public-looking IP."""
    return f"{random.randint(1, 223)}.{random.randint(0, 254)}.{random.randint(0, 254)}.{random.randint(1, 254)}"


def _random_timestamp(hours_back: int = 2) -> str:
    """Generate a random ISO timestamp within the last N hours."""
    now = datetime.now(tz=timezone.utc)
    delta = timedelta(seconds=random.randint(0, hours_back * 3600))
    return (now - delta).isoformat()


def generate_event(index: int) -> dict[str, Any]:
    """Generate a single realistic XDR event document."""
    host = random.choice(HOSTS)
    event_type = random.choice(EVENT_TYPES)
    severity = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0]
    signature = random.choice(SIGNATURES[event_type])

    event: dict[str, Any] = {
        "host": host,
        "event_type": event_type,
        "severity": severity,
        "source_ip": _random_private_ip(),
        "dest_ip": _random_public_ip() if random.random() > 0.3 else _random_private_ip(),
        "signature": signature,
        "timestamp": _random_timestamp(hours_back=2),
        "kafka_topic": KAFKA_TOPIC,
        "kafka_offset": index,
    }

    # Add optional security fields with 50-70% probability
    if random.random() > 0.3:
        event["mitre_technique"] = random.choice(MITRE_TECHNIQUES[event_type])
    if random.random() > 0.4:
        event["process_name"] = random.choice(PROCESS_NAMES)
    if random.random() > 0.5:
        event["username"] = random.choice(USERNAMES)
    if random.random() > 0.7:
        event["container_name"] = random.choice(CONTAINER_NAMES)
    if random.random() > 0.8:
        event["device_name"] = f"DEV-{random.randint(100, 999)}"

    # Occasionally add a payload field
    if random.random() > 0.75:
        payloads = {
            "Malware": f"Shellcode detected in process {event.get('process_name', 'unknown')}",
            "Phishing": "HTML attachment with embedded credential harvesting form",
            "Scan": f"SYN scan from {event['source_ip']} — {random.randint(100, 5000)} ports probed",
            "Exfil": f"{random.randint(1, 100)}MB uploaded to external endpoint",
            "Ransomware": "File system encryption detected — .locked extension",
            "LateralMovement": f"SMB connection to {event['dest_ip']} — pass-the-hash suspected",
        }
        event["payload"] = payloads.get(event_type, "Suspicious activity detected")

    return event


# ---------------------------------------------------------------------------
# Producer
# ---------------------------------------------------------------------------

def create_producer() -> KafkaProducer:
    """Create a KafkaProducer with JSON serialization."""
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(","),
        value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else None,
        acks="all",
        retries=3,
        max_in_flight_requests_per_connection=1,
        compression_type="gzip",
    )


def seed_events(count: int = 100, topic: str = KAFKA_TOPIC) -> None:
    """Send `count` fake XDR events to the Kafka topic."""
    log.info(
        "Connecting to Kafka at %s | topic=%s | count=%d",
        KAFKA_BOOTSTRAP_SERVERS,
        topic,
        count,
    )

    try:
        producer = create_producer()
    except KafkaError as exc:
        log.error("Failed to create Kafka producer: %s", exc)
        sys.exit(1)

    success = 0
    errors = 0

    for i in range(count):
        event = generate_event(i)
        key = f"{event['host']}_{event['event_type']}"

        try:
            future = producer.send(topic, value=event, key=key)
            future.get(timeout=10)  # Block until confirmed
            success += 1

            if (i + 1) % 20 == 0:
                log.info("Progress: %d/%d events sent", i + 1, count)

        except KafkaError as exc:
            log.error("Failed to send event %d: %s", i, exc)
            errors += 1

        # Small delay to avoid overwhelming the broker
        time.sleep(0.05)

    producer.flush()
    producer.close()

    log.info(
        "Seeding complete. ✅ Sent: %d | ❌ Failed: %d | Topic: %s",
        success,
        errors,
        topic,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed XDR events to Kafka")
    parser.add_argument("--count", type=int, default=100, help="Number of events to send (default: 100)")
    parser.add_argument("--topic", type=str, default=KAFKA_TOPIC, help="Kafka topic name")
    args = parser.parse_args()

    seed_events(count=args.count, topic=args.topic)
