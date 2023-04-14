from flask import Flask              
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider        
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
import logging


def configure_tracer() -> None:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    logger.info("Configuring tracer...")

    trace.set_tracer_provider(TracerProvider())
    trace.get_tracer_provider().add_span_processor(
        BatchSpanProcessor(
            JaegerExporter(
                agent_host_name='jaeger',
                agent_port=6831,
            )
        )
    )

    # For seeing traces in the console
    trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    logger.info("Tracer configured.")