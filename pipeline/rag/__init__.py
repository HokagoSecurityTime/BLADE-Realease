"""Retrieval is setup-only and imports no heavy packages when disabled."""
import os

from common.features import enabled
from common.schema import EvidenceRef
from pipeline.parsers.erd import TableInfo
from pipeline.parsers.oas import Endpoint


def retrieve(endpoint: Endpoint, erd_info: dict[str, TableInfo]) -> list[EvidenceRef]:
    if not enabled('BLADE_RAG_ENABLED'):
        return []
    from pipeline.rag.index import Index
    from pipeline.rag.corpus import load_idioms
    index = Index()
    if not index.collections['idiom'].count():
        index.replace('idiom', load_idioms())
    kinds = os.getenv('BLADE_RAG_KINDS', 'code,idiom,policy,cve').split(',')
    return index.retrieve(endpoint, erd_info, kinds=[k.strip() for k in kinds if k.strip()])
