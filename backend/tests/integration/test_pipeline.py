from app.ingestion.scapy import ScapyParser
from app.ingestion.test_source import TestTrafficSource
from app.engine.pipeline import build_pipeline
from app.schemas.traffic import FlowRecord


class TestPipelineIntegration:
    def test_synthetic_flow_processing(self):
        import asyncio

        async def run():
            pipeline = build_pipeline()
            await pipeline.start()
            source = TestTrafficSource(flows_per_second=5, seed=2)
            records = source.generate_batch(5)
            flow_ids = await pipeline.submit_batch(records)
            assert len(flow_ids) == 5

            for flow_id, record in zip(flow_ids, records):
                result = await pipeline.process(flow_id, record)
                if result is not None:
                    assert "decision" in result
            await pipeline.stop()

        asyncio.run(run())