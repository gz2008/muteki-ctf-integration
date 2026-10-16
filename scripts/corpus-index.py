"""Build or query a BM25 index over the offline CTF corpora.

Literal ripgrep needs the right keyword; a BM25 index answers natural-language
questions ("how do I exploit a tcache use after free") with ranked passages.

Usage:
  python corpus-index.py build [--root DIR] [--out DIR]
  python corpus-index.py query --out DIR "question" [-n 8]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import bm25s

DEFAULT_ROOT = Path("/mnt/d/codex/output/muteki-ctf-integration/muteki-tool-root")
DEFAULT_OUT = Path("/mnt/d/codex/output/muteki-ctf-integration/index/bm25")

# Only prose-like sources: template yaml and images add noise, not answers.
CORPORA = (
    "knowledges/PayloadsAllTheThings",
    "knowledges/InternalAllTheThings",
    "knowledges/hacktricks",
    "knowledges/hacktricks-cloud",
    "knowledges/how2heap",
    "knowledges/ctf-wiki",
    "pocs/vulhub",
    "pocs/Awesome-POC",
)
TEXT_SUFFIXES = {".md", ".markdown", ".txt", ".rst", ".py", ".c", ".yml", ".yaml", ".json", ".html"}
MAX_FILE_BYTES = 400_000
CHUNK_CHARS = 1400
CHUNK_OVERLAP = 200

# BM25's whitespace/alphanumeric splitter turns a Chinese sentence into a few
# very long tokens, so a Chinese corpus is effectively unsearchable. Character
# bigrams are the standard fix: index them alongside the original text and
# expand the query the same way.
CJK_RUN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\u3040-\u30ff]+")


def cjk_bigrams(text: str) -> list[str]:
    bigrams: list[str] = []
    for run in CJK_RUN.findall(text):
        if len(run) == 1:
            bigrams.append(run)
        else:
            bigrams.extend(run[index:index + 2] for index in range(len(run) - 1))
    return bigrams


def searchable(text: str) -> str:
    return text + "\n" + " ".join(cjk_bigrams(text))


def iter_chunks(root: Path):
    for corpus in CORPORA:
        base = root / corpus
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            relative = str(path.relative_to(root))
            length = len(text)
            start = 0
            while start < length:
                piece = text[start:start + CHUNK_CHARS].strip()
                if len(piece) > 120:
                    yield {
                        "text": piece.replace("\n", " "),
                        "path": relative,
                        "title": str(path.relative_to(base)),
                        "corpus": corpus.split("/")[-1],
                        "offset": start,
                    }
                start += CHUNK_CHARS - CHUNK_OVERLAP


def build(root: Path, out: Path) -> int:
    docs = list(iter_chunks(root))
    if not docs:
        print("no documents found; is the tool root populated?", file=sys.stderr)
        return 2
    corpus = [doc["text"] for doc in docs]
    # Index the path and title with the body: "tcache_poisoning.c" is a much
    # stronger signal than the same words buried in a code chunk.
    documents = [
        searchable(f"{doc['path']} {doc['title']}\n{doc['text']}") for doc in docs
    ]
    tokens = bm25s.tokenize(documents, stopwords="en", show_progress=False)
    retriever = bm25s.BM25()
    retriever.index(tokens, show_progress=False)
    out.mkdir(parents=True, exist_ok=True)
    # Store the metadata dicts with the index so a query needs no sidecar file.
    retriever.save(str(out), corpus=docs)
    (out / "meta.json").write_text(
        json.dumps({"documents": docs, "chunks": len(docs)}, ensure_ascii=False),
        encoding="utf-8",
    )
    print(json.dumps({"chunks": len(docs), "out": str(out)}))
    return 0


def query(out: Path, question: str, limit: int, dedupe: bool = True) -> int:
    meta_path = out / "meta.json"
    if not meta_path.is_file():
        print(f"index not found at {out}; run build first", file=sys.stderr)
        return 3
    meta = json.loads(meta_path.read_text(encoding="utf-8"))["documents"]
    retriever = bm25s.BM25.load(str(out), load_corpus=True)
    tokens = bm25s.tokenize([searchable(question)], stopwords="en", show_progress=False)
    # how2heap and similar trees repeat one file across glibc versions; ask for a
    # deeper list and keep the best-scoring chunk per file so distinct sources
    # reach the top of the answer.
    depth = limit * 6 if dedupe else limit
    results, scores = retriever.retrieve(tokens, k=depth, show_progress=False)
    rank = 0
    seen: set[tuple[str, str]] = set()
    for item, score in zip(results[0], scores[0]):
        if isinstance(item, dict):
            doc = item
        elif isinstance(item, str):
            doc = next((row for row in meta if row["text"] == item), meta[0])
        else:
            doc = meta[int(item)]
        if dedupe:
            key = (doc["corpus"], doc["title"].rsplit("/", 1)[-1])
            if key in seen:
                continue
            seen.add(key)
        rank += 1
        snippet = doc["text"][:220]
        print(f"{rank:2d}. [{score:.2f}] [{doc['corpus']}] {doc['path']} (+{doc['offset']})")
        print(f"    {snippet}")
        if rank >= limit:
            break
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build_parser = sub.add_parser("build")
    build_parser.add_argument("--root", default=str(DEFAULT_ROOT))
    build_parser.add_argument("--out", default=str(DEFAULT_OUT))
    query_parser = sub.add_parser("query")
    query_parser.add_argument("question")
    query_parser.add_argument("--out", default=str(DEFAULT_OUT))
    query_parser.add_argument("-n", type=int, default=8)
    query_parser.add_argument("--no-dedupe", action="store_true")
    args = parser.parse_args()
    if args.command == "build":
        return build(Path(args.root), Path(args.out))
    return query(Path(args.out), args.question, args.n, dedupe=not args.no_dedupe)


if __name__ == "__main__":
    raise SystemExit(main())
