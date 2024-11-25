import asyncio
from typing import Optional, Type

from langchain.prompts import ChatPromptTemplate
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.output_parser import StrOutputParser
from langchain.tools import BaseTool
from pydantic import BaseModel


class QueryToSigmaRuleInput(BaseModel):
    """Input for QueryToSigmaRuleTool."""

    query: str
    backend: Optional[str] = None


class QueryToSigmaRuleTool(BaseTool):
    """Class for converting queries to Sigma rules"""

    name: str = "query_to_sigma_rule"
    args_schema: Type[BaseModel] = QueryToSigmaRuleInput
    description: str = """
Use this tool to convert a query from a security product/SIEM into a Sigma Rule.
The input should be the query string and optionally the backend/product name.
The output will be a Sigma Rule in YAML format.
"""
    llm: BaseLanguageModel
    verbose: bool = False

    def _run(
        self,
        query: str,
        backend: Optional[str] = None,
    ) -> str:
        return asyncio.run(self._arun(query, backend))

    async def _arun(
        self,
        query: Optional[str] = None,
        backend: Optional[str] = None,
    ) -> str:
        template = """You are a cybersecurity detection engineering assistant bot specializing in Sigma Rule creation.
You are assisting a user in taking a query for a security/SIEM product, and converting it to a Sigma Rule.
The backend is used to validate the query and ensure it is compatible with the backend.
The created Sigma Rule should be in YAML format and use the official Sigma schema.  The detection field
can contain multiple 'selection' identifiers and multiple 'filter' identifiers as needed, 
which can be used in the condition field to select criteria and filter out criteria respectively.  
The fields should be Sysmon field names if possible, or Windows Event Log field names if possible.  

-----------

Sigma Rule Schema:

title
id [optional]
related [optional]
   - id {{rule-id}}
     type {{type-identifier}}
status [optional]
description [optional]
references [optional]
author [optional]
date [optional]
modified [optional]
tags [optional]
logsource
   category [optional]
   product [optional]
   service [optional]
   definition [optional]
   ...
detection
   {{search-identifier}} [optional]
      {{string-list}} [optional]
      {{map-list}} [optional]
      {{field: value}} [optional]
   ... # Multiple search identifiers can be specified as needed and used in the condition
   condition
fields [optional]
falsepositives [optional]
level [optional]

-----------

User's Query: {query}
Backend: {backend}
"""

        prompt = ChatPromptTemplate.from_template(template)
        chain = prompt | self.llm | StrOutputParser()
        return await chain.ainvoke({"query": query, "backend": backend})
