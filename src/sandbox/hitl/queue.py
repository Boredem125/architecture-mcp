"""Redis-backed HITL pending review queue.

Manages a FIFO queue of actions awaiting human review, backed by Redis
sorted sets (scored by timeout timestamp) and hashes (for random access
by request_id).  Timeout enforcement auto-denies stale requests.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import orjson
import redis.asyncio as aioredis
import structlog

from sandbox.models.enums import HITLDecision
from sandbox.models.messages import HITLContextPackage, HITLResult

logger = structlog.get_logger(__name__)

# Redis key namespace
_QUEUE_KEY = "hitl:pending"          # sorted set: request_id scored by timeout_at
_ITEM_PREFIX = "hitl:item:"          # hash per item: {request_id} -> JSON blob
_STATS_KEY = "hitl:stats"            # hash: counters and aggregates
_DECIDED_PREFIX = "hitl:decided:"    # hash per decision: {request_id} -> HITLResult JSON


class HITLQueue:
    """Async Redis-backed HITL review queue.

    Items are stored in a sorted set keyed by their ``timeout_at_utc``
    timestamp so that :meth:`check_timeouts` can range-scan efficiently.
    Full context packages live in per-request hashes for O(1) random
    access.

    Args:
        redis_url: Redis connection URL.  Database 1 is the conventional
            HITL database per :class:`sandbox.config.RedisSettings`.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/1") -> None:
        self._redis_url = redis_url
        self._redis: aioredis.Redis | None = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Establish the async Redis connection pool."""
        if self._redis is not None:
            logger.debug("hitl_queue.already_connected")
            return
        self._redis = aioredis.from_url(
            self._redis_url,
            decode_responses=False,
        )
        # Verify connectivity.
        await self._redis.ping()
        logger.info("hitl_queue.connected", url=self._redis_url)

    async def disconnect(self) -> None:
        """Close the Redis connection pool gracefully."""
        if self._redis is None:
            return
        await self._redis.aclose()
        self._redis = None
        logger.info("hitl_queue.disconnected")

    # ------------------------------------------------------------------
    # Queue operations
    # ------------------------------------------------------------------

    async def enqueue(self, context: HITLContextPackage) -> str:
        """Add a review request to the pending queue.

        The item is stored in both a sorted set (for ordered retrieval
        and timeout scanning) and a hash (for random access).

        Args:
            context: Fully assembled HITL context package.

        Returns:
            The queue position ID (the ``request_id`` from the context).
        """
        r = self._ensure_connected()

        timeout_ts = self._parse_timeout(context.timeout_at_utc)
        payload = orjson.dumps(context.model_dump())

        pipe = r.pipeline(transaction=True)
        pipe.zadd(_QUEUE_KEY, {context.request_id.encode(): timeout_ts})
        pipe.set(f"{_ITEM_PREFIX}{context.request_id}", payload)
        pipe.hincrby(_STATS_KEY, "total_enqueued", 1)
        await pipe.execute()

        position = await r.zrank(_QUEUE_KEY, context.request_id.encode())
        logger.info(
            "hitl_queue.enqueued",
            request_id=context.request_id,
            risk_tier=context.risk_tier,
            timeout_at=context.timeout_at_utc,
            position=position,
        )
        return context.request_id

    async def dequeue(self, reviewer_id: str) -> HITLContextPackage | None:
        """Pop the next pending request for this reviewer (FIFO).

        Atomically removes the lowest-scored (earliest enqueued by
        timeout) member from the sorted set and deletes its hash entry.

        Args:
            reviewer_id: Identifier of the reviewer claiming the item.

        Returns:
            The context package, or ``None`` if the queue is empty.
        """
        r = self._ensure_connected()

        # ZPOPMIN returns the member with the lowest score (FIFO by timeout).
        result = await r.zpopmin(_QUEUE_KEY, count=1)
        if not result:
            return None

        member, _score = result[0]
        request_id = member.decode() if isinstance(member, bytes) else member

        raw = await r.get(f"{_ITEM_PREFIX}{request_id}")
        if raw is None:
            logger.warning(
                "hitl_queue.dequeue_orphan",
                request_id=request_id,
            )
            return None

        await r.delete(f"{_ITEM_PREFIX}{request_id}")

        context = HITLContextPackage.model_validate(orjson.loads(raw))
        logger.info(
            "hitl_queue.dequeued",
            request_id=request_id,
            reviewer_id=reviewer_id,
        )
        return context

    async def peek(self) -> list[HITLContextPackage]:
        """List all pending requests without removing them.

        Returns items ordered by timeout (earliest deadline first).
        """
        r = self._ensure_connected()

        members = await r.zrange(_QUEUE_KEY, 0, -1)
        items: list[HITLContextPackage] = []

        for member in members:
            request_id = member.decode() if isinstance(member, bytes) else member
            raw = await r.get(f"{_ITEM_PREFIX}{request_id}")
            if raw is None:
                continue
            items.append(HITLContextPackage.model_validate(orjson.loads(raw)))

        return items

    async def submit_decision(
        self,
        request_id: str,
        decision: HITLDecision,
        reviewer_id: str,
        reason: str,
    ) -> HITLResult:
        """Record a reviewer's decision for a pending request.

        Removes the item from the pending queue and stores the outcome
        for auditing.

        Args:
            request_id: The request being decided upon.
            decision: APPROVE or DENY.
            reviewer_id: Who made the decision.
            reason: Free-text justification.

        Returns:
            The finalised HITL result.

        Raises:
            KeyError: If ``request_id`` is not in the pending queue.
        """
        r = self._ensure_connected()

        raw = await r.get(f"{_ITEM_PREFIX}{request_id}")
        if raw is None:
            raise KeyError(f"Request {request_id} not found in pending queue")

        context = HITLContextPackage.model_validate(orjson.loads(raw))

        # Compute review latency from timeout_at minus original timeout
        # duration; approximate using wall-clock.
        enqueue_score = await r.zscore(_QUEUE_KEY, request_id.encode())
        now_ms = int(time.time() * 1000)
        latency_ms: int | None = None
        if enqueue_score is not None:
            timeout_ts = float(enqueue_score)
            # We stored the timeout deadline as the score, so elapsed =
            # now - (score - original_timeout).  Since we don't store
            # enqueue time separately, use a simpler approximation.
            latency_ms = max(0, now_ms - int((timeout_ts - 600) * 1000))

        result = HITLResult(
            request_id=request_id,
            decision=decision,
            reviewer_id=reviewer_id,
            reason=reason,
            latency_ms=latency_ms,
        )

        pipe = r.pipeline(transaction=True)
        pipe.zrem(_QUEUE_KEY, request_id.encode())
        pipe.delete(f"{_ITEM_PREFIX}{request_id}")
        pipe.set(
            f"{_DECIDED_PREFIX}{request_id}",
            orjson.dumps(result.model_dump()),
            ex=86400,  # keep decisions for 24 h
        )
        pipe.hincrby(_STATS_KEY, "total_decided", 1)
        if latency_ms is not None:
            pipe.hincrbyfloat(_STATS_KEY, "total_latency_ms", float(latency_ms))
        await pipe.execute()

        logger.info(
            "hitl_queue.decision_submitted",
            request_id=request_id,
            decision=decision,
            reviewer_id=reviewer_id,
        )
        return result

    async def check_timeouts(self) -> list[HITLResult]:
        """Scan for timed-out pending requests and auto-deny them.

        Returns a list of :class:`HITLResult` objects for every request
        whose ``timeout_at_utc`` has passed.
        """
        r = self._ensure_connected()

        now_ts = datetime.now(timezone.utc).timestamp()
        timed_out_members = await r.zrangebyscore(
            _QUEUE_KEY, "-inf", now_ts,
        )

        results: list[HITLResult] = []
        for member in timed_out_members:
            request_id = member.decode() if isinstance(member, bytes) else member

            result = HITLResult(
                request_id=request_id,
                decision=HITLDecision.TIMEOUT,
                reviewer_id=None,
                reason="Review window expired — auto-denied per timeout policy",
            )

            pipe = r.pipeline(transaction=True)
            pipe.zrem(_QUEUE_KEY, member)
            pipe.delete(f"{_ITEM_PREFIX}{request_id}")
            pipe.set(
                f"{_DECIDED_PREFIX}{request_id}",
                orjson.dumps(result.model_dump()),
                ex=86400,
            )
            pipe.hincrby(_STATS_KEY, "total_timeouts", 1)
            pipe.hincrby(_STATS_KEY, "total_decided", 1)
            await pipe.execute()

            results.append(result)
            logger.warning(
                "hitl_queue.timeout",
                request_id=request_id,
            )

        return results

    async def get_pending_count(self) -> int:
        """Return the number of items currently awaiting review."""
        r = self._ensure_connected()
        count: int = await r.zcard(_QUEUE_KEY)
        return count

    async def get_stats(self) -> dict:
        """Return queue statistics.

        Returns:
            Dict with ``pending_count``, ``avg_wait_ms``, and
            ``timeout_rate``.
        """
        r = self._ensure_connected()

        pending_count = await self.get_pending_count()
        raw_stats = await r.hgetall(_STATS_KEY)

        # Decode bytes keys/values from Redis.
        stats: dict[str, str] = {}
        for k, v in raw_stats.items():
            key = k.decode() if isinstance(k, bytes) else k
            val = v.decode() if isinstance(v, bytes) else v
            stats[key] = val

        total_decided = int(stats.get("total_decided", "0"))
        total_latency = float(stats.get("total_latency_ms", "0"))
        total_timeouts = int(stats.get("total_timeouts", "0"))
        total_enqueued = int(stats.get("total_enqueued", "0"))

        avg_wait_ms = (total_latency / total_decided) if total_decided > 0 else 0.0
        timeout_rate = (
            (total_timeouts / total_enqueued) if total_enqueued > 0 else 0.0
        )

        return {
            "pending_count": pending_count,
            "avg_wait_ms": round(avg_wait_ms, 1),
            "timeout_rate": round(timeout_rate, 4),
            "total_enqueued": total_enqueued,
            "total_decided": total_decided,
            "total_timeouts": total_timeouts,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_connected(self) -> aioredis.Redis:
        """Return the Redis client or raise if not connected."""
        if self._redis is None:
            raise RuntimeError(
                "HITLQueue is not connected. Call 'await queue.connect()' first."
            )
        return self._redis

    @staticmethod
    def _parse_timeout(timeout_at_utc: str) -> float:
        """Parse an ISO-8601 timestamp into a Unix epoch float.

        Falls back to ``time.time() + 600`` (10 min) if the string is
        empty or unparseable.
        """
        if not timeout_at_utc:
            return time.time() + 600.0
        try:
            dt = datetime.fromisoformat(timeout_at_utc)
            return dt.timestamp()
        except (ValueError, TypeError):
            logger.warning(
                "hitl_queue.bad_timeout_format",
                timeout_at_utc=timeout_at_utc,
            )
            return time.time() + 600.0
