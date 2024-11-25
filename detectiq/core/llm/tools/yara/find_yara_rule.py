import asyncio
from typing import Type, Union

from langchain.prompts import ChatPromptTemplate
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough
from langchain.schema.vectorstore import VectorStore
from langchain.tools import BaseTool
from pydantic import BaseModel


class FindYaraRuleInput(BaseModel):
    """Input for FindYaraRuleTool."""

    query: Union[str, dict]


class FindYaraRuleTool(BaseTool):
    """Class for searching YARA rules in the vector database"""

    name: str = "find_yara_rule"
    args_schema: Type[BaseModel] = FindYaraRuleInput
    description: str = """
Use this tool to search for a YARA Rule in the vector database. The input should be relevant information, such as
file characteristics, malware signatures, patterns, or other relevant information to use
to search the vector store. If multiple rules are returned from the vector store, select the most similar YARA Rule.
"""
    llm: BaseLanguageModel
    yaradb: VectorStore
    k: int = 3
    verbose: bool = False

    def _run(self, query: Union[str, dict]) -> str:
        return asyncio.run(self._arun(query))

    async def _arun(self, query: Union[str, dict]) -> str:
        template = """You are a malware analyst specializing in YARA rules.
You are assisting a user searching for YARA Rules stored in a vectorstore.
Based on the user's question, extract the relevant information, such as
file characteristics, malware signatures, patterns, or other relevant information to use
to search the vector store. If multiple rules are returned from the 
vector store, select the most similar YARA Rule. Output the entire rule.
-------
Vectorstore Search Results:

{context}
------
User's Question: 
{question}
"""

        prompt = ChatPromptTemplate.from_template(template)
        retriever = self.yaradb.as_retriever(search_kwargs={"k": self.k})
        chain = {"context": retriever, "question": RunnablePassthrough()} | prompt | self.llm | StrOutputParser()
        return await chain.ainvoke(query)
