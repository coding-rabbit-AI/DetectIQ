import asyncio
from pathlib import Path
from typing import Optional, Type

from langchain.prompts import ChatPromptTemplate
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.output_parser import StrOutputParser
from langchain.tools import BaseTool
from pydantic import BaseModel, Field

from detectiq.core.utils.snort.pcap_analyzer import PcapAnalyzer


class AnalyzePcapInput(BaseModel):
    """Input for AnalyzePcapTool."""

    pcap_path: str
    max_packets: Optional[int] = 10000
    include_payload: Optional[bool] = True


class AnalyzePcapTool(BaseTool):
    """Class for analyzing PCAP files and identifying patterns for Snort rules"""

    name: str = "analyze_pcap"
    args_schema: Type[BaseModel] = AnalyzePcapInput
    description: str = """
    Use this tool to analyze a PCAP file and identify network patterns, protocols,
    and characteristics that can be used to create Snort rules for network detection
    while avoiding false positives.
    """
    llm: BaseLanguageModel
    verbose: bool = False
    analyzer: PcapAnalyzer = Field(default_factory=lambda: PcapAnalyzer())

    def _run(
        self,
        pcap_path: str,
    ) -> str:
        """Synchronous run method required by BaseTool."""
        return asyncio.run(self._arun(pcap_path))

    async def _arun(
        self,
        pcap_path: str,
    ) -> str:
        # Extract PCAP information using the analyzer
        pcap_info = await self.analyzer.analyze_file(Path(pcap_path))

        template = """You are a network security analyst specializing in Snort rule creation.
Based on the PCAP analysis, identify the most significant patterns for creating effective Snort rules.
Focus on the most suspicious or notable traffic patterns that would be useful for detection.

PCAP Analysis Results:
{pcap_info}

Provide a focused analysis of:
1. Most distinctive traffic patterns that should be included in rules
2. Specific packet characteristics to use in rules
3. Recommended rule options to minimize false positives
4. Top priority patterns to detect
"""

        prompt = ChatPromptTemplate.from_template(template)
        chain = prompt | self.llm | StrOutputParser()
        return await chain.ainvoke({"pcap_info": pcap_info})
