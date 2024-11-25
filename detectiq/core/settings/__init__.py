from .base import SettingsManager

settings_manager = SettingsManager()
settings = settings_manager.settings

__all__ = ["settings", "settings_manager"]
