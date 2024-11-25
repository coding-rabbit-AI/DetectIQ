# stdlib
from typing import List

# langchain
from langchain.tools import BaseTool

# rule toolkits
from detectiq.core.llm.toolkits.base import BaseRuleToolkit

# langchain typing
# sigmaiq tools
from detectiq.core.llm.tools.sigma import (
    CreateSigmaRuleTool,
    FindSigmaRuleTool,
    TranslateSigmaRuleTool,
)


class SigmaToolkit(BaseRuleToolkit):
    """Sigma Rule Toolkit."""

    def get_tools(self) -> List[BaseTool]:
        """Get the tools in the toolkit."""
        tools: List[BaseTool] = [
            TranslateSigmaRuleTool(llm=self.rule_creation_llm),
            CreateSigmaRuleTool(llm=self.rule_creation_llm, sigmadb=self.vectordb),
            FindSigmaRuleTool(llm=self.rule_creation_llm, sigmadb=self.vectordb),
        ]
        return tools
