"""Local sentence-transformers embeddings with persistent, isolated collections."""
from dataclasses import asdict
from functools import lru_cache
import json
import os
from pathlib import Path
from typing import Any, Protocol

from common.schema import EvidenceRef
from pipeline.parsers.erd import TableInfo
from pipeline.parsers.oas import Endpoint
from pipeline.rag.corpus import Chunk

WEIGHTS = {'code': 1.0, 'idiom': .8, 'policy': .8, 'cve': .4}


class Encoder(Protocol):
    name: str
    def encode(self, texts: list[str], *, query: bool = False) -> list[list[float]]: ...


@lru_cache(maxsize=1)
def _model(name: str, cache: str) -> Any:
    os.environ.setdefault('HF_HUB_DISABLE_TELEMETRY', '1')
    os.environ.setdefault('HF_HOME', str(Path(cache).parent/'huggingface'))
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer(name, cache_folder=cache, device='cpu', trust_remote_code=False)


class LocalEncoder:
    def __init__(self) -> None:
        self.name = os.getenv('BLADE_EMBED_MODEL', 'intfloat/multilingual-e5-small')
        self.cache = str(Path(os.getenv('BLADE_MODEL_CACHE', '.cache/models')).resolve())

    def encode(self, texts: list[str], *, query: bool = False) -> list[list[float]]:
        prefix = 'query: ' if query else 'passage: '
        model = _model(self.name, self.cache)
        return model.encode([prefix + text for text in texts], normalize_embeddings=True,
                            show_progress_bar=False).tolist()


class Index:
    def __init__(self, path: str | Path | None = None, encoder: Encoder | None = None) -> None:
        import chromadb
        from chromadb.config import Settings
        self.encoder = encoder or LocalEncoder()
        self.client = chromadb.PersistentClient(path=str(path or os.getenv('BLADE_CHROMA_PATH', '.chroma')),
                                               settings=Settings(anonymized_telemetry=False))
        self.collections = {}
        for kind in WEIGHTS:
            collection = self.client.get_or_create_collection('blade_' + kind, embedding_function=None,
                metadata={'hnsw:space': 'cosine', 'embedding_model': self.encoder.name})
            if collection.metadata.get('embedding_model') != self.encoder.name:
                raise ValueError('Embedding model changed; use a separate BLADE_CHROMA_PATH')
            self.collections[kind] = collection

    def replace(self, kind: str, chunks: list[Chunk]) -> None:
        collection = self.collections[kind]
        unique = {chunk.id: chunk for chunk in chunks if chunk.kind == kind}
        existing = set(collection.get(include=[])['ids'])
        stale = existing - unique.keys()
        if stale:
            collection.delete(ids=sorted(stale))
        new = [chunk for key, chunk in unique.items() if key not in existing]
        for start in range(0, len(new), 64):
            batch = new[start:start+64]
            collection.upsert(ids=[c.id for c in batch], documents=[c.text for c in batch],
                              metadatas=[dict(kind=c.kind, ref=c.ref) for c in batch],
                              embeddings=self.encoder.encode([c.text for c in batch]))

    def retrieve(self, endpoint: Endpoint, erd_info: dict[str, TableInfo], *,
                 kinds: list[str] | None = None, top_k: int = 5) -> list[EvidenceRef]:
        if top_k <= 0:
            raise ValueError('top_k must be positive')
        query = json.dumps(dict(endpoint=asdict(endpoint), tables={k: asdict(v) for k, v in erd_info.items()}), ensure_ascii=False)
        embedding = self.encoder.encode([query], query=True)
        matches: list[tuple[float, EvidenceRef]] = []
        for kind in kinds if kinds is not None else list(WEIGHTS):
            collection = self.collections[kind]
            count = collection.count()
            if not count:
                continue
            result = collection.query(query_embeddings=embedding, n_results=min(top_k, count),
                                      include=['documents', 'metadatas', 'distances'])
            for text, metadata, distance in zip(result['documents'][0], result['metadatas'][0], result['distances'][0]):
                score = (1 - distance) * WEIGHTS[kind]
                matches.append((score, EvidenceRef(kind=kind, ref=metadata['ref'], snippet=text[:600])))
        matches.sort(key=lambda row: (-row[0], row[1].kind, row[1].ref))
        return [ref for _, ref in matches[:top_k]]
