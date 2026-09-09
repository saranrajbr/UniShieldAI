import asyncio

from app.alerts.manager import AlertManager
from app.capture.flow_pcap import flow_pcap_recorder
from app.core.config import settings
from app.core.logging import get_logger
from app.decision.engine import DecisionEngine, decision_engine
from app.features.extractor import FeatureExtractor
from app.features.statistics import record_flow, record_packet
from app.ml.engine import MLEngine
from app.rules.engine import RuleEngine, build_engine
from app.rules.registry import RuleRegistry
from app.schemas.traffic import FlowRecord
from app.state.connection_tracker import connection_tracker
from app.state.flow_state import FlowState, flow_state
from app.utils.hashing import flow_hash
from app.utils.metrics import runtime_metrics

logger = get_logger("unishield.pipeline")


class DetectionPipeline:
    def __init__(
        self,
        flow_state_: FlowState | None = None,
        rule_engine: RuleEngine | None = None,
        ml_engine: MLEngine | None = None,
        decision: DecisionEngine | None = None,
        alert_manager: AlertManager | None = None,
    ) -> None:
        self.flow_state = flow_state_ or flow_state
        if rule_engine is None:
            rule_engine = build_engine(load_defaults=True)
        self.rules = rule_engine
        self.ml = ml_engine or MLEngine()
        self.decision = decision or decision_engine
        self.alert_manager = alert_manager or AlertManager()
        self.extractor = FeatureExtractor()
        self._queue: asyncio.Queue | None = None
        self._worker: asyncio.Task | None = None
        self._workers: list[asyncio.Task] = []

    async def start(self, workers: int = 1) -> None:
        self._queue = asyncio.Queue(maxsize=settings.pipeline_queue_size)
        self._workers = [
            asyncio.create_task(self._consume(), name=f"pipeline-consumer-{i}")
            for i in range(workers)
        ]
        self._worker = self._workers[0]
        logger.info("Detection pipeline started (%d consumers)", workers)

    async def stop(self) -> None:
        for w in self._workers:
            w.cancel()
        self._workers = []
        self._worker = None

    async def submit(self, record: FlowRecord) -> str | None:
        if self._queue is None:
            return None
        flow_id = flow_hash(
            record.src_ip, record.dst_ip, record.src_port, record.dst_port, record.protocol
        )
        try:
            if self._queue.full():
                runtime_metrics.record_error()
                return None
            await self._queue.put((flow_id, record))
            return flow_id
        except asyncio.QueueFull:
            runtime_metrics.record_error()
            return None

    async def submit_batch(self, records: list[FlowRecord]) -> list[str]:
        ids: list[str] = []
        for record in records:
            flow_id = await self.submit(record)
            if flow_id:
                ids.append(flow_id)
        return ids

    async def _consume(self) -> None:
        while True:
            flow_id, record = await self._queue.get()
            try:
                await self.process(flow_id, record)
            except Exception:
                runtime_metrics.record_error()
                logger.exception("Pipeline stage failed for flow %s", flow_id)
            finally:
                self._queue.task_done()

    async def process(self, flow_id: str, record: FlowRecord) -> dict | None:
        runtime_metrics.record_flow()
        record_flow()
        record_packet(record.byte_count)
        flow_pcap_recorder.record(
            record.src_ip, record.dst_ip, record.protocol,
            record.src_port, record.dst_port, record.byte_count,
            syn=record.syn_count, ack=record.ack_count,
            rst=record.rst_count, fin=record.fin_count,
        )

        entry = self.flow_state.get_or_create(
            flow_id,
            record.src_ip,
            record.dst_ip,
            record.src_port,
            record.dst_port,
            record.protocol,
        )
        record_ts = record.ts.timestamp() if record.ts else None
        self.flow_state.update(
            entry,
            packet_count=record.packet_count,
            byte_count=record.byte_count,
            syn_count=record.syn_count,
            ack_count=record.ack_count,
            rst_count=record.rst_count,
            fin_count=record.fin_count,
            ts=record_ts,
        )

        conn = connection_tracker.touch(
            record.src_ip,
            record.dst_ip,
            record.src_port,
            record.dst_port,
            record.protocol,
            packet_size=record.byte_count,
        )

        features = self.extractor.extract_from_entry(entry, dns_query=record.dns_query)
        if record.tls_ja3:
            features.tls_ja3 = record.tls_ja3

        rule_assessment = await asyncio.to_thread(self.rules.result_assessment, features.model_dump())
        if rule_assessment["matched_rule_count"]:
            runtime_metrics.rules_fired += 1

        ml_assessment = await asyncio.to_thread(self.ml.inference.run, features.model_dump())
        runtime_metrics.ml_inferences += 1

        decision = self.decision.decide(flow_id, rule_assessment, ml_assessment)

        result = {
            "flow_id": flow_id,
            "features": features,
            "rule_assessment": rule_assessment,
            "ml_assessment": ml_assessment,
            "decision": decision,
            "record": record,
        }

        if decision.is_threat:
            await self._handle_threat(result, conn)

        runtime_metrics.queue_high_watermark = max(
            runtime_metrics.queue_high_watermark, self._queue.qsize() if self._queue else 0
        )
        return result

    async def _handle_threat(self, result: dict, conn) -> None:
        decision = result["decision"]
        features = result["features"]
        alert = self.alert_manager.create_alert(decision, features)

        if alert is None:
            return
        runtime_metrics.alerts_raised += 1

        try:
            from app.alerts.evidence import EvidenceCollector
            collector = EvidenceCollector()
            from datetime import datetime, timezone
            forever = await asyncio.to_thread(
                collector.preserve_for_incident,
                alert.alert_id,
                decision.threat_type.value,
                str(int(datetime.now(timezone.utc).timestamp())),
            )
            if forever:
                self.alert_manager.set_pcap_path(alert.alert_id, str(forever))
        except Exception:
            logger.exception("Evidence preservation failed")

    @property
    def queue_size(self) -> int:
        return self._queue.qsize() if self._queue else 0


def build_pipeline(rule_registry: RuleRegistry | None = None) -> DetectionPipeline:
    engine = build_engine(load_defaults=True)
    return DetectionPipeline(rule_engine=engine)


pipeline = DetectionPipeline()