# stdlib
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type

# langchain
from langchain.agents.agent import AgentExecutor
from langchain.agents.agent_toolkits.base import BaseToolkit
from langchain.agents.format_scratchpad import format_to_openai_function_messages
from langchain.agents.output_parsers import OpenAIFunctionsAgentOutputParser
from langchain.prompts import ChatPromptTemplate
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.vectorstore import VectorStore
from langchain.tools import BaseTool

# langchain typing
from langchain_core.utils.function_calling import convert_to_openai_function

from detectiq.core.llm.toolkits.prompts import (
    SIGMA_AGENT_PROMPT,
    SNORT_AGENT_PROMPT,
    YARA_AGENT_PROMPT,
)

# sigmaiq


class BaseRuleToolkit(BaseToolkit, ABC):
    """Abstract base class for rule toolkits."""

    vectordb: VectorStore
    rule_creation_llm: BaseLanguageModel

    class Config:
        arbitrary_types_allowed = True

    @abstractmethod
    def get_tools(self) -> List[BaseTool]:
        """Get the tools in the toolkit."""
        pass


def create_rule_agent(
    rule_type: str,
    vectorstore: VectorStore,
    rule_creation_llm: BaseLanguageModel,
    agent_llm: BaseLanguageModel,
    toolkit_class: Type[BaseRuleToolkit],
    prompt: Optional[ChatPromptTemplate] = None,
    verbose: bool = False,
    return_intermediate_steps: bool = False,
    agent_executor_kwargs: Optional[Dict[str, Any]] = None,
) -> AgentExecutor:
    """Create a rule agent."""
    toolkit = toolkit_class(vectordb=vectorstore, rule_creation_llm=rule_creation_llm)
    tools = toolkit.get_tools()

    if prompt is None:
        if rule_type.lower() == "sigma":
            prompt = SIGMA_AGENT_PROMPT
        elif rule_type.lower() == "snort":
            prompt = SNORT_AGENT_PROMPT
        elif rule_type.lower() == "yara":
            prompt = YARA_AGENT_PROMPT
        else:
            raise ValueError(f"No default prompt available for rule type: {rule_type}")

    llm_with_tools = agent_llm.bind(functions=[convert_to_openai_function(t) for t in tools])

    agent = (
        {
            "input": lambda x: x["input"],
            "agent_scratchpad": lambda x: format_to_openai_function_messages(x["intermediate_steps"]),
            "chat_history": lambda x: x.get("chat_history", []),  # Make chat_history optional
        }
        | prompt
        | llm_with_tools
        | OpenAIFunctionsAgentOutputParser()
    )

    executor_kwargs = {
        "agent": agent,
        "tools": tools,
        "verbose": verbose,
        "return_intermediate_steps": return_intermediate_steps,
    }

    if agent_executor_kwargs:
        executor_kwargs.update(agent_executor_kwargs)

    return AgentExecutor(**executor_kwargs)
