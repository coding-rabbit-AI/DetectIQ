from typing import List

from langchain.tools import BaseTool

from detectiq.core.llm.toolkits.base import BaseRuleToolkit
from detectiq.core.llm.tools.snort import (
    AnalyzePcapTool,
    CreateSnortRuleTool,
    FindSnortRuleTool,
)


class SnortToolkit(BaseRuleToolkit):
    """Snort Rule Toolkit."""

    def get_tools(self) -> List[BaseTool]:
        """Get the tools in the toolkit."""
        # Create analyze tool first since it's often used before create
        analyze_tool = AnalyzePcapTool(llm=self.rule_creation_llm)

        # Create rule tool that will use the analysis results
        create_tool = CreateSnortRuleTool(llm=self.rule_creation_llm, snortdb=self.vectordb)

        # Find tool for searching existing rules
        find_tool = FindSnortRuleTool(llm=self.rule_creation_llm, snortdb=self.vectordb)

        return [analyze_tool, create_tool, find_tool]
