from langchain_community.llms import Ollama
from langchain_community.document_loaders import PyPDFLoader
from langchain_community.document_loaders import TextLoader
import glob
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_core.prompts import ChatPromptTemplate
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain.chains import create_retrieval_chain
import os

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url=OLLAMA_BASE_URL)

# 設定知識文件路徑
#pdf_path = "knowledge/your_docs.pdf"  # 請將你的知識 PDF 放在 knowledge 資料夾，並改名

llm = Ollama(model="mistral", base_url=OLLAMA_BASE_URL)  # 你也可以換成 llama2、phi 等
#loader = PyPDFLoader(pdf_path)
loader = TextLoader("knowledge/test.txt")  # 如果你有其他格式的文件，可以使用相應的 loader
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

context = []
input_text = input("您想問什麼問題？\n>>> ")

while input_text.lower() != "bye":
    response = retrieval_chain.invoke({"input": input_text, "context": context})
    context = response["context"]
    print(response["answer"])
    input_text = input(">>> ") 
    
