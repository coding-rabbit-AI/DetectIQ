import asyncio
from typing import Type, Union

from langchain.prompts import ChatPromptTemplate
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough
from langchain.schema.vectorstore import VectorStore
from langchain.tools import BaseTool
from pydantic import BaseModel


class FindSnortRuleInput(BaseModel):
    """Input for FindSnortRuleTool."""

    query: Union[str, dict]


class FindSnortRuleTool(BaseTool):
    """Class for searching Snort rules in the vector database"""

    name: str = "find_snort_rule"
    args_schema: Type[BaseModel] = FindSnortRuleInput
    description: str = """
Use this tool to search for a Snort Rule in the vector database. The input should be relevant information, such as
protocol information, packet characteristics, signatures, or other relevant information to use
to search the vector store. If multiple rules are returned from the vector store, select the most similar Snort Rule.
"""
    llm: BaseLanguageModel
    snortdb: VectorStore
    k: int = 3
    verbose: bool = False

    def _run(self, query: Union[str, dict]) -> str:
        return asyncio.run(self._arun(query))

    async def _arun(self, query: Union[str, dict]) -> str:
        template = """You are a cybersecurity detection engineering assistant bot specializing in Snort Rules.
You are assisting a user searching for Snort Rules stored in a vectorstore.
Based on the user's question, extract the relevant information, such as
protocol information, packet characteristics, signatures, or other relevant information to use
to search the vector store. If multiple rules are returned from the 
vector store, select the most similar Snort Rule. Output the entire rule.
-------
Vectorstore Search Results:

{context}
------
User's Question: 
{question}
"""

        prompt = ChatPromptTemplate.from_template(template)
        retriever = self.snortdb.as_retriever(search_kwargs={"k": self.k})
        chain = {"context": retriever, "question": RunnablePassthrough()} | prompt | self.llm | StrOutputParser()
        return await chain.ainvoke(query)
