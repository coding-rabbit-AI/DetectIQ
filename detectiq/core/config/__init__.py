from .base import ConfigManager

config_manager = ConfigManager()
config = config_manager.config

__all__ = ["config", "config_manager"]
