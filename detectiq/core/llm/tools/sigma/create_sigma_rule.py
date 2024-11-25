import asyncio
import re
from datetime import datetime
from typing import Any, Dict, Optional, Type

import yaml
from langchain.prompts import ChatPromptTemplate
from langchain.schema.language_model import BaseLanguageModel
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough
from langchain.schema.vectorstore import VectorStore
from langchain.tools import BaseTool
from pydantic import BaseModel

from detectiq.core.utils.logging import get_logger

# Initialize logger
logger = get_logger(__name__)


class CreateSigmaRuleInput(BaseModel):
    """Input for CreateSigmaRuleTool."""

    description: str
    rule_context: Optional[str] = None


class CreateSigmaRuleTool(BaseTool):
    """Class for creating Sigma rules based on log analysis or description"""

    name: str = "create_sigma_rule"
    args_schema: Type[BaseModel] = CreateSigmaRuleInput
    description: str = """
Use this tool to create Sigma rules based on either:
1. Log analysis results
2. A description of what you want to detect

The tool will generate appropriate Sigma rules to detect similar patterns
while avoiding false positives.
"""
    llm: BaseLanguageModel
    sigmadb: VectorStore
    k: int = 3
    verbose: bool = False

    async def _arun(
        self,
        description: str,
        rule_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        try:
            # Get current date
            current_date = datetime.now().strftime("%Y-%m-%d")

            # Get similar rules silently
            retriever = self.sigmadb.as_retriever(search_kwargs={"k": self.k})
            similar_rules = await retriever.ainvoke(description)

            # Format similar rules context
            context_text = "\n".join(doc.page_content for doc in similar_rules)

            template = """You are an expert in creating Sigma rules.

Given the following description and context, produce a Sigma rule that effectively detects the specified threat while minimizing false positives.

Context (Similar Rules):
{context_text}

Description:
{description}

Additional Context:
{rule_context}

Ensure your Sigma rule includes:

- A unique 'id' (UUID)
- Clear 'title' and 'description'
- Appropriate 'author', 'date', 'references', 'tags', and 'level'
- Correct 'logsource' definition
- Add authors of any rules used as context for rule creation
- Well-defined 'detection' section with selections and conditions
- 'falsepositives' section listing potential false positives
- 'related' field if similar rules are used

Example:

```yaml
id: <unique UUID>
title: <Title of the rule>
description: <Description of the rule>
author: <DetectIQ, and any other authors>
date: {current_date}
related:
  - id: <UUID>
    type: <derived, similar, obsolete, renamed, or merged>
references:
  - <URLs or documents>
logsource:
  category: <category>
  product: <product>
  service: <service>
detection:
  selections:
    field: value
  filters:
    field: value
  condition: <logical condition>
falsepositives:
  - <Possible false positives>
level: <informational, low, medium, high, critical>
tags:
  - <MITRE ATT&CK tags>
```

Follow the Sigma documentation for proper formatting: https://sigmahq.io/docs/basics/rules.html

The Analysis Summary and Detection Strategy sections are required and must be detailed.

You MUST provide your response in the following format:

=== Analysis Summary ===
[Provide a detailed analysis of:
1. The attack technique or behavior being detected
2. Key indicators and patterns identified
3. Relevant log sources and fields
4. Potential variations of the attack]

=== Detection Strategy ===
[Explain in detail:
1. Why specific detection logic was chosen
2. How the conditions work together
3. Why certain fields were selected
4. How false positives are minimized
5. Any limitations or considerations]

=== Sigma Rule ===
[Provide the Sigma rule in valid YAML format, following best practices. Only put the Sigma rule in the YAML block.]
"""

            prompt = ChatPromptTemplate.from_template(template)
            chain = (
                {
                    "context_text": lambda x: context_text,
                    "description": RunnablePassthrough(),
                    "rule_context": lambda x: rule_context or "No additional context provided.",
                    "current_date": lambda x: current_date,
                }
                | prompt
                | self.llm
                | StrOutputParser()
            )

            response = await chain.ainvoke(description)

            # First try to extract from code block
            yaml_block_match = re.search(r"```yaml\n(.*?)\n```", response, re.DOTALL)
            if yaml_block_match:
                rule_content = yaml_block_match.group(1).strip()
            else:
                # Fallback to section extraction
                yaml_match = re.search(r"=== Sigma Rule ===\n(.*?)(?=\n===|$)", response, re.DOTALL)
                if not yaml_match:
                    raise ValueError("Could not extract Sigma rule from response")
                rule_content = yaml_match.group(1).strip()

            # Extract the analysis sections
            analysis_summary = re.search(r"=== Analysis Summary ===\n(.*?)(?=\n===)", response, re.DOTALL)
            detection_strategy = re.search(r"=== Detection Strategy ===\n(.*?)(?=\n===)", response, re.DOTALL)

            if not analysis_summary or not detection_strategy:
                logger.warning("Missing required analysis sections in response")
                raise ValueError("Response missing required analysis sections")

            # Combine analysis sections for agent output
            agent_output = ""
            agent_output += "=== Analysis Summary ===\n" + analysis_summary.group(1).strip() + "\n\n"
            agent_output += "=== Detection Strategy ===\n" + detection_strategy.group(1).strip()

            if not agent_output.strip():
                logger.warning("Empty agent output generated")
                raise ValueError("Empty analysis sections in response")

            # Clean up the rule content - improved YAML extraction
            yaml_lines = []
            in_yaml = False
            for line in rule_content.split("\n"):
                stripped_line = line.strip()
                # Start capturing at title: or --- (YAML document start)
                if stripped_line.startswith("id:") or stripped_line == "---":
                    in_yaml = True
                if in_yaml:
                    # Stop if we hit explanatory text or empty lines after YAML
                    if (stripped_line and not ":" in stripped_line and not stripped_line.startswith("-")) or (
                        not stripped_line and len(yaml_lines) > 0 and not any(l.strip() for l in yaml_lines[-3:])
                    ):
                        break
                    yaml_lines.append(line)

            rule_content = "\n".join(yaml_lines).strip()

            # Parse the YAML content to extract title and other fields
            try:
                rule_yaml = yaml.safe_load(rule_content)
                if not rule_yaml or not isinstance(rule_yaml, dict):
                    logger.warning("Invalid YAML structure, using fallback values")
                    title = "Untitled Rule"
                    severity = "medium"
                    description = ""
                else:
                    title = rule_yaml.get("title", "Untitled Rule")
                    severity = rule_yaml.get("level", "medium")
                    description = rule_yaml.get("description", "")
            except Exception as e:
                logger.warning(f"Failed to parse YAML content: {e}")
                title = "Untitled Rule"
                severity = "medium"
                description = ""

            # Validate severity before returning
            valid_severities = ["informational", "low", "medium", "high", "critical"]
            severity = severity.lower()
            if severity not in valid_severities:
                severity = "medium"

            return {
                "rule": rule_content,
                "agent_output": agent_output,
                "title": title,
                "severity": severity,
                "description": description,
            }

        except Exception as e:
            logger.error(f"Error creating Sigma rule: {e}")
            raise

    def _run(
        self,
        description: str,
        rule_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Synchronous run method required by BaseTool."""
        return asyncio.run(self._arun(description, rule_context))
