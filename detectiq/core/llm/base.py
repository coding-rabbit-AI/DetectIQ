# stdlib
import asyncio
import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, cast

from langchain.embeddings.base import Embeddings
from langchain.schema.document import Document
from langchain.schema.language_model import BaseLanguageModel
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings

from detectiq.core.utils.logging import get_logger
from detectiq.globals import DEFAULT_DIRS

logger = get_logger(__name__)


class BaseLLMRules(ABC):
    """Base class for LLM-powered rule operations."""

    def __init__(
        self,
        embedding_model: Optional[Embeddings] = None,
        agent_llm: Optional[BaseLanguageModel] = None,
        rule_creation_llm: Optional[BaseLanguageModel] = None,
        rule_dir: Optional[str] = None,
        vector_store_dir: Optional[str] = None,
        auto_update: bool = True,
    ):
        """Initialize base class.

        Args:
            embedding_model: Model for creating embeddings
            agent_llm: LLM for agent operations
            rule_creation_llm: LLM for rule creation
            rule_dir: Directory for rules
            vector_store_dir: Directory for vector store
            auto_update: Whether to automatically update rules
        """
        self.embedding_model = embedding_model
        self.agent_llm = agent_llm
        self.rule_creation_llm = rule_creation_llm

        # Use proper attribute access for DEFAULT_DIRS
        default_rule_dir = getattr(DEFAULT_DIRS, "RULE_DIR", Path("rules"))
        default_vector_dir = getattr(DEFAULT_DIRS, "VECTOR_STORE_DIR", Path("vector_store"))

        self.rule_dir = Path(rule_dir) if rule_dir else default_rule_dir
        self.vector_store_dir = Path(vector_store_dir) if vector_store_dir else default_vector_dir
        self.auto_update = auto_update
        self.vectordb: Optional[FAISS] = None

        # Ensure directories exist
        self.rule_dir.mkdir(parents=True, exist_ok=True)
        self.vector_store_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Initialized {self.__class__.__name__} with rule directory: {self.rule_dir}")

    def load_vectordb(self) -> None:
        """Load vector store from disk."""
        try:
            logger.info(f"Loading vector store from {self.vector_store_dir}")
            if not self.embedding_model:
                raise ValueError("Embedding model not initialized")

            if not os.path.exists(self.vector_store_dir):
                raise FileNotFoundError(f"Vector store not found at {self.vector_store_dir}")

            self.vectordb = FAISS.load_local(
                folder_path=str(self.vector_store_dir),
                embeddings=self.embedding_model,
                allow_dangerous_deserialization=True,
            )
            logger.info("Vector store loaded successfully")

        except Exception as e:
            logger.error(f"Failed to load vector store: {str(e)}")
            raise

    async def create_vectordb(
        self, texts: Optional[List[str]] = None, metadatas: Optional[List[Dict[str, Any]]] = None
    ) -> None:
        """Create vector store from documents."""
        try:
            logger.info("Creating vector store from documents")
            if not self.embedding_model:
                raise ValueError("Embedding model not initialized")

            # Get documents if not provided
            if not texts or not metadatas:
                documents = await self.create_rule_docs()
                texts = [doc.page_content for doc in documents]
                metadatas = [doc.metadata for doc in documents]

            # Create vector store
            self.vectordb = FAISS.from_texts(
                texts=texts,
                metadatas=metadatas,
                embedding=self.embedding_model,
            )

            # Save vector store
            self.vectordb.save_local(str(self.vector_store_dir))
            logger.info("Vector store created and saved successfully")

        except Exception as e:
            logger.error(f"Failed to create vector store: {str(e)}")
            raise

    @abstractmethod
    async def update_rules(self, force: bool = False) -> None:
        """Update rules from source."""
        pass

    @abstractmethod
    async def create_rule_docs(self) -> List[Document]:
        """Create Document objects from rules."""
        pass

    def split_rule_docs(self, documents: List[Document]) -> List[Document]:
        """Do not split documents to preserve rule context."""
        return documents
