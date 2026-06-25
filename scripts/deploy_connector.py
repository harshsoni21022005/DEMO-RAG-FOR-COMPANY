"""
scripts/deploy_connector.py

Deploy the Kafka Connect MongoDB Sink Connector.

Reads config/kafka_sink_connector.json and POSTs it to the Kafka Connect
REST API. Handles the case where the connector already exists (uses PUT
to update instead of POST to create).

Replaces the MongoDB URI placeholder in the connector config with the
actual value from the environment before deploying.

Usage:
    python scripts/deploy_connector.py
    python scripts/deploy_connector.py --config config/kafka_sink_connector.json
    python scripts/deploy_connector.py --delete  # Remove the connector
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] deploy_connector — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KAFKA_CONNECT_URL: str = os.getenv("KAFKA_CONNECT_URL", "http://localhost:8083").rstrip("/")
MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DEFAULT_CONFIG_PATH: Path = Path(__file__).parent.parent / "config" / "kafka_sink_connector.json"


# ---------------------------------------------------------------------------
# Wait for Kafka Connect to be ready
# ---------------------------------------------------------------------------

def wait_for_connect(timeout_s: int = 120) -> bool:
    """Poll the Kafka Connect REST API until it becomes available."""
    log.info("Waiting for Kafka Connect at %s ...", KAFKA_CONNECT_URL)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            resp = httpx.get(f"{KAFKA_CONNECT_URL}/connectors", timeout=5.0)
            if resp.status_code == 200:
                log.info("Kafka Connect is ready [OK]")
                return True
        except (httpx.ConnectError, httpx.RemoteProtocolError, httpx.ReadError, httpx.TimeoutException):
            pass
        except Exception as exc:
            log.debug("Unexpected error while waiting: %s", exc)
        log.info("Kafka Connect not ready yet, retrying in 5s...")
        time.sleep(5)
    log.error("Kafka Connect did not become ready within %ds.", timeout_s)
    return False


# ---------------------------------------------------------------------------
# Connector management
# ---------------------------------------------------------------------------

def load_config(config_path: Path) -> dict[str, Any]:
    """Load connector config JSON and inject environment variables."""
    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)

    # Inject the actual MongoDB URI from the environment
    # (replacing the file-based secrets reference with the actual URI)
    if "config" in config:
        config["config"]["connection.uri"] = MONGODB_URI
        log.info("Injected MONGODB_URI into connector config.")

    return config


def get_existing_connectors() -> list[str]:
    """Return list of currently deployed connector names."""
    try:
        resp = httpx.get(f"{KAFKA_CONNECT_URL}/connectors", timeout=10.0)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        log.error("Failed to list connectors: %s", exc)
        return []


def deploy_connector(config: dict[str, Any]) -> bool:
    """
    Deploy or update the connector.

    Uses POST /connectors to create; PUT /connectors/{name}/config to update.
    """
    connector_name = config.get("name")
    if not connector_name:
        log.error("Connector config missing 'name' field.")
        return False

    existing = get_existing_connectors()

    if connector_name in existing:
        log.info("Connector '%s' already exists — updating via PUT.", connector_name)
        url = f"{KAFKA_CONNECT_URL}/connectors/{connector_name}/config"
        try:
            resp = httpx.put(
                url,
                json=config.get("config", {}),
                timeout=30.0,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            log.info("Connector '%s' updated successfully [OK]", connector_name)
            return True
        except httpx.HTTPStatusError as exc:
            log.error("Failed to update connector: %s — %s", exc, exc.response.text)
            return False
        except Exception as exc:
            log.error("Error updating connector: %s", exc)
            return False
    else:
        log.info("Creating new connector '%s' via POST.", connector_name)
        url = f"{KAFKA_CONNECT_URL}/connectors"
        try:
            resp = httpx.post(
                url,
                json=config,
                timeout=30.0,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            log.info("Connector '%s' created successfully [OK]", connector_name)
            log.info("Response: %s", resp.json())
            return True
        except httpx.HTTPStatusError as exc:
            log.error("Failed to create connector: %s — %s", exc, exc.response.text)
            return False
        except Exception as exc:
            log.error("Error creating connector: %s", exc)
            return False


def delete_connector(name: str) -> bool:
    """Delete a connector by name."""
    log.info("Deleting connector '%s'...", name)
    try:
        resp = httpx.delete(f"{KAFKA_CONNECT_URL}/connectors/{name}", timeout=15.0)
        resp.raise_for_status()
        log.info("Connector '%s' deleted [OK]", name)
        return True
    except httpx.HTTPStatusError as exc:
        log.error("Failed to delete connector: %s — %s", exc, exc.response.text)
        return False
    except Exception as exc:
        log.error("Error deleting connector: %s", exc)
        return False


def check_connector_status(name: str) -> None:
    """Log the current status of a deployed connector."""
    try:
        resp = httpx.get(f"{KAFKA_CONNECT_URL}/connectors/{name}/status", timeout=10.0)
        resp.raise_for_status()
        status = resp.json()
        connector_state = status.get("connector", {}).get("state", "UNKNOWN")
        tasks = status.get("tasks", [])
        log.info(
            "Connector '%s' status: %s | Tasks: %s",
            name,
            connector_state,
            [(t["id"], t["state"]) for t in tasks],
        )
    except Exception as exc:
        log.warning("Could not fetch connector status: %s", exc)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy the Kafka Connect MongoDB Sink Connector")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Path to connector config JSON file",
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Delete the connector instead of deploying",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        default=True,
        help="Wait for Kafka Connect to be ready before deploying",
    )
    args = parser.parse_args()

    # Wait for Kafka Connect
    if args.wait:
        if not wait_for_connect():
            sys.exit(1)

    # Load config
    config = load_config(args.config)
    connector_name = config.get("name", "xdr-mongodb-sink")

    if args.delete:
        success = delete_connector(connector_name)
        sys.exit(0 if success else 1)

    # Deploy
    success = deploy_connector(config)
    if success:
        time.sleep(2)  # Brief pause for the connector to initialize
        check_connector_status(connector_name)
    else:
        sys.exit(1)
