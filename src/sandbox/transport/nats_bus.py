"""NATS message-bus wrapper for the agent sandbox pipeline.

Provides :class:`MessageBus` — a thin async façade over ``nats-py`` and
JetStream that handles connection lifecycle, publish/subscribe,
request/reply, and :class:`MessageEnvelope` serialisation with optional
cryptographic signing.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from typing import Any

import nats
import orjson
import structlog
from nats.aio.client import Client as NATSClient
from nats.aio.msg import Msg
from nats.js.client import JetStreamContext

from sandbox.models.messages import MessageEnvelope

logger = structlog.get_logger(__name__)


class MessageBus:
    """Async NATS message bus for inter-agent communication.

    Wraps connection management, pub/sub, request/reply, JetStream
    stream provisioning, and envelope-aware publishing.

    Args:
        url: NATS server URL (or comma-separated cluster URLs).
    """

    def __init__(self, url: str = "nats://localhost:4222") -> None:
        self._url = url
        self._nc: NATSClient | None = None
        self._js: JetStreamContext | None = None
        self._subscriptions: list[Any] = []

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Establish a connection to the NATS server.

        Configures automatic reconnection and logs lifecycle events via
        *structlog*.  Safe to call more than once — subsequent calls are
        no-ops while the connection is alive.
        """
        if self._nc is not None and self._nc.is_connected:
            logger.debug("nats.already_connected", url=self._url)
            return

        async def _on_disconnect(conn: NATSClient) -> None:
            logger.warning("nats.disconnected", url=self._url)

        async def _on_reconnect(conn: NATSClient) -> None:
            logger.info("nats.reconnected", url=self._url)

        async def _on_error(conn: NATSClient, sub: Any, error: Exception) -> None:
            logger.error("nats.error", error=str(error), url=self._url)

        async def _on_closed(conn: NATSClient) -> None:
            logger.info("nats.connection_closed", url=self._url)

        self._nc = await nats.connect(
            servers=self._url,
            max_reconnect_attempts=10,
            reconnect_time_wait=2.0,
            disconnected_cb=_on_disconnect,
            reconnected_cb=_on_reconnect,
            error_cb=_on_error,
            closed_cb=_on_closed,
        )
        self._js = self._nc.jetstream()
        logger.info("nats.connected", url=self._url)

    async def disconnect(self) -> None:
        """Drain subscriptions and close the connection gracefully."""
        if self._nc is None or self._nc.is_closed:
            return
        try:
            await self._nc.drain()
        except Exception:
            logger.warning("nats.drain_error", exc_info=True)
        finally:
            self._nc = None
            self._js = None
            self._subscriptions.clear()
            logger.info("nats.disconnected_clean")

    # ------------------------------------------------------------------
    # Core pub/sub
    # ------------------------------------------------------------------

    async def publish(
        self,
        subject: str,
        data: bytes,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Publish raw bytes to a NATS subject.

        Args:
            subject: The NATS subject to publish on.
            data: Raw payload bytes.
            headers: Optional NATS message headers.
        """
        self._ensure_connected()
        assert self._nc is not None  # for type narrowing
        await self._nc.publish(subject, data, headers=headers)
        logger.debug("nats.published", subject=subject, size=len(data))

    async def subscribe(
        self,
        subject: str,
        handler: Callable[[Msg], Any],
        queue_group: str = "",
    ) -> Any:
        """Subscribe to a NATS subject.

        Args:
            subject: Subject pattern (may include wildcards).
            handler: Async callback invoked for each message.
            queue_group: Optional queue-group name for load-balanced
                consumption across multiple instances.

        Returns:
            The NATS subscription object (can be used to unsubscribe).
        """
        self._ensure_connected()
        assert self._nc is not None
        sub = await self._nc.subscribe(subject, cb=handler, queue=queue_group)
        self._subscriptions.append(sub)
        logger.info(
            "nats.subscribed",
            subject=subject,
            queue_group=queue_group or "(none)",
        )
        return sub

    async def request(
        self,
        subject: str,
        data: bytes,
        timeout: float = 5.0,
    ) -> bytes:
        """Send a request and wait for a single reply.

        Args:
            subject: Target subject.
            data: Request payload.
            timeout: Maximum seconds to wait for a reply.

        Returns:
            The reply payload bytes.

        Raises:
            nats.errors.TimeoutError: If no reply arrives within *timeout*.
        """
        self._ensure_connected()
        assert self._nc is not None
        response: Msg = await self._nc.request(subject, data, timeout=timeout)
        logger.debug(
            "nats.request_reply",
            subject=subject,
            reply_size=len(response.data),
        )
        return response.data

    # ------------------------------------------------------------------
    # JetStream helpers
    # ------------------------------------------------------------------

    async def create_stream(self, name: str, subjects: list[str]) -> None:
        """Create (or update) a JetStream stream for durable persistence.

        Args:
            name: Stream name (alphanumeric + dashes).
            subjects: List of subjects the stream captures.
        """
        self._ensure_connected()
        assert self._js is not None
        await self._js.add_stream(name=name, subjects=subjects)
        logger.info("nats.stream_created", stream=name, subjects=subjects)

    # ------------------------------------------------------------------
    # Envelope-aware publishing
    # ------------------------------------------------------------------

    async def publish_message(
        self,
        envelope: MessageEnvelope,
        subject: str,
        signing_key: bytes | None = None,
    ) -> None:
        """Serialise a :class:`MessageEnvelope` to JSON and publish it.

        If *signing_key* is provided the envelope's ``signature`` field is
        populated with an HMAC-SHA256 hex digest computed over the
        canonical JSON payload before transmission.

        Args:
            envelope: The message envelope to send.
            subject: NATS subject to publish on.
            signing_key: Optional HMAC key for message authentication.
        """
        raw = orjson.dumps(envelope.model_dump())

        if signing_key is not None:
            sig = hmac.new(signing_key, raw, hashlib.sha256).hexdigest()
            envelope.signature = sig
            # Re-serialise with the signature embedded.
            raw = orjson.dumps(envelope.model_dump())

        headers = {
            "X-Msg-Id": envelope.msg_id,
            "X-Session-Id": envelope.session_id,
            "X-Sender": envelope.sender,
        }
        await self.publish(subject, raw, headers=headers)
        logger.debug(
            "nats.envelope_published",
            subject=subject,
            msg_id=envelope.msg_id,
            signed=signing_key is not None,
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_connected(self) -> bool:
        """``True`` when the underlying NATS client has an active connection."""
        return self._nc is not None and self._nc.is_connected

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_connected(self) -> None:
        """Raise immediately if we have no live connection."""
        if not self.is_connected:
            raise RuntimeError(
                "MessageBus is not connected. Call 'await bus.connect()' first."
            )
