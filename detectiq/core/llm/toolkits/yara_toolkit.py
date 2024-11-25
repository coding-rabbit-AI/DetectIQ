from typing import List

from langchain.tools import BaseTool

from detectiq.core.llm.toolkits.base import BaseRuleToolkit
from detectiq.core.llm.tools.yara import (
    AnalyzeFileTool,
    CreateYaraRuleTool,
    FindYaraRuleTool,
    ScanFileTool,
)


class YaraToolkit(BaseRuleToolkit):
    """YARA Rule Toolkit."""

    def get_tools(self) -> List[BaseTool]:
        return [
            FindYaraRuleTool(yaradb=self.vectordb, llm=self.rule_creation_llm),
            CreateYaraRuleTool(yaradb=self.vectordb, llm=self.rule_creation_llm),
            AnalyzeFileTool(llm=self.rule_creation_llm),
            ScanFileTool(llm=self.rule_creation_llm),
        ]
