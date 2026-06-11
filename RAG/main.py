import glob
import os
from typing import List

import requests
import uvicorn
from fastapi import FastAPI, Request
from langchain.chains import create_retrieval_chain
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import PyPDFLoader, TextLoader
from langchain_community.llms import Ollama
from langchain_community.vectorstores import Chroma
from langchain_core.embeddings import Embeddings
from langchain_core.prompts import ChatPromptTemplate

OLLAMA_BASE_URL  = os.getenv("OLLAMA_BASE_URL",  "http://host.docker.internal:11434")
OLLAMA_LLM_MODEL = os.getenv("OLLAMA_LLM_MODEL", "llama3.1")
CHROMA_DB_DIR = "db"
KNOWLEDGE_DIR = "knowledge"


class SmartOllamaEmbeddings(Embeddings):
    """Embeds text via nomic-embed-text.

    - embed_documents: normal keep_alive (stays loaded for fast batch indexing)
    - embed_query:     keep_alive=0 so the model unloads from VRAM before
                       llama3 needs to run (they can't coexist in VRAM)
    """

    def __init__(self, model: str, base_url: str):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def _embed(self, text: str, keep_alive: str = "5m", num_gpu: int = -1) -> List[float]:
        payload = {
            "model": self.model,
            "prompt": text,
            "keep_alive": keep_alive,
            "options": {"num_gpu": num_gpu},
        }
        resp = requests.post(
            f"{self.base_url}/api/embeddings",
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["embedding"]

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        # Batch indexing: keep on GPU (first run only, then DB is persisted)
        return [self._embed(t, keep_alive="5m", num_gpu=-1) for t in texts]

    def embed_query(self, text: str) -> List[float]:
        # Query time: run on CPU (num_gpu=0) so llama3.1 can keep its VRAM
        return self._embed(text, keep_alive="0", num_gpu=0)


embeddings = SmartOllamaEmbeddings(model="nomic-embed-text", base_url=OLLAMA_BASE_URL)
llm = Ollama(model=OLLAMA_LLM_MODEL, base_url=OLLAMA_BASE_URL, timeout=120)

# nomic-embed-text context limit is tight; 200 chars keeps every chunk safe
splitter = RecursiveCharacterTextSplitter(
    chunk_size=200,
    chunk_overlap=20,
    separators=["\n\n", "\n", "。", ".", " ", ""],
)

# Load and split knowledge-base documents
all_docs = []
for file_path in glob.glob(f"{KNOWLEDGE_DIR}/*"):
    try:
        if file_path.endswith(".txt"):
            loader = TextLoader(file_path, encoding="utf-8")
        elif file_path.endswith(".pdf"):
            loader = PyPDFLoader(file_path)
        else:
            continue
        docs = loader.load()
        all_docs.extend(splitter.split_documents(docs))
        print(f"[RAG] Loaded: {os.path.basename(file_path)}")
    except Exception as e:
        print(f"[RAG] Skipped {file_path}: {e}")

_db_ready = os.path.exists(os.path.join(CHROMA_DB_DIR, "chroma.sqlite3"))

if _db_ready:
    # Load existing vector store — Ollama not needed at startup
    vector_db = Chroma(
        persist_directory=CHROMA_DB_DIR,
        embedding_function=embeddings,
        collection_name="nids_knowledge",
    )
    print("[RAG] Loaded existing ChromaDB — skipping re-index")
else:
    # First run: build from knowledge files (requires Ollama)
    vector_db = Chroma.from_documents(
        documents=all_docs,
        embedding=embeddings,
        persist_directory=CHROMA_DB_DIR,
        collection_name="nids_knowledge",
    )
    print(f"[RAG] Built ChromaDB from {len(all_docs)} document chunks")
    # Unload embedding model so llama3.1 can use full VRAM
    try:
        requests.post(
            f"{OLLAMA_BASE_URL}/api/embeddings",
            json={"model": "nomic-embed-text", "prompt": "", "keep_alive": 0},
            timeout=10,
        )
        print("[RAG] nomic-embed-text unloaded from VRAM")
    except Exception:
        pass

retriever = vector_db.as_retriever(search_kwargs={"k": 3})

system_prompt = (
    "You are a cybersecurity expert.\n"
    "You will be given context in Chinese.\n"
    "You must respond ONLY in the following exact format, in English. "
    "Do not translate. Do not explain. Do not write more than 30 words in the summary.\n\n"
    "For the suggestions, provide three concise and actionable recommendations based on the context.\n\n"
    "---\n"
    "Message Summary: <one sentence summary here>\n\n"
    "Suggestions:\n"
    "1. ...\n"
    "2. ...\n"
    "3. ...\n"
    "---\n\n"
    "This is mandatory. If you deviate from this structure, your response will be invalid.\n"
    "If you cannot answer based on the context, reply exactly: 'I don't know.'\n\n"
    "Here is the context:\n\n{context}"
)

prompt_template = ChatPromptTemplate.from_messages(
    [
        ("system", system_prompt),
        ("user", "Question: {input}"),
    ]
)

document_chain = create_stuff_documents_chain(llm, prompt_template)
retrieval_chain = create_retrieval_chain(retriever, document_chain)

app = FastAPI(title="NIDS RAG Summary API")


@app.post("/summary")
async def summary(request: Request):
    data = await request.json()
    text: str = data.get("text", "").strip()
    if not text:
        return {"summary": "(No input text provided)"}
    result = retrieval_chain.invoke({"input": text})
    return {"summary": result.get("answer", "(AI could not generate a summary)")}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
