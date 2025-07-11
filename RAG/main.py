from fastapi import FastAPI, Request
import uvicorn
from langchain_community.llms import Ollama
from langchain_community.document_loaders import TextLoader
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_core.prompts import ChatPromptTemplate
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain
import os

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url=OLLAMA_BASE_URL)

llm = Ollama(model="mistral", base_url=OLLAMA_BASE_URL)
loader = TextLoader("knowledge/test.txt")  # 你的知識庫檔案
splited_docs = loader.load_and_split()

vector_db = Chroma.from_documents(
    documents=splited_docs,
    embedding=embeddings,
    persist_directory="db",
    collection_name="interview",
)

retriever = vector_db.as_retriever(search_kwargs={"k": 3})

system_prompt = "你是資安專家，請根據下列情境回答問題，只能用繁體中文，不要有簡體字。如果不知道答案就說不知道。情境如下:\n\n{context}"
prompt_template = ChatPromptTemplate.from_messages(
    [
        ("system", system_prompt),
        ("user", "問題: {input}"),
    ]
)

document_chain = create_stuff_documents_chain(llm, prompt_template)
retrieval_chain = create_retrieval_chain(retriever, document_chain)

app = FastAPI()

@app.post("/summary")
async def summary(request: Request):
    data = await request.json()
    text = data.get("text", "")
    if not text:
        return {"summary": "（未提供要摘要的內容）"}
    response = retrieval_chain.invoke({"input": text, "context": []})
    summary = response.get("answer", "（AI無法產生摘要）")
    return {"summary": summary}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000) 
    
