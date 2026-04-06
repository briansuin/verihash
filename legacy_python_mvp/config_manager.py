import os
import json
from typing import Dict, Any

CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "watchdog_target_dir": "./test_workspace",
    "ai_mode": "local",
    "local_model_name": "phi3",
    "cloud_base_url": "https://api.deepseek.com/chat/completions",
    "cloud_model_name": "deepseek-chat",
    "cloud_api_key": "",
    "last_minted_snapshot_id": 0
}

def load_config() -> Dict[str, Any]:
    """
    Load configuration from config.json.
    Missing keys will be populated with default values.
    """
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
                
                # Merge with defaults to ensure all keys exist
                merged = DEFAULT_CONFIG.copy()
                merged.update(config)
                return merged
        except Exception as e:
            print(f"[ERROR] Loading config failed: {e}. Falling back to defaults.")
            return DEFAULT_CONFIG.copy()
    else:
        # Initialize default config file
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

def save_config(config_data: Dict[str, Any]) -> bool:
    """
    Save configuration dict to config.json.
    """
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=4)
        return True
    except Exception as e:
        print(f"[ERROR] Saving config failed: {e}")
        return False
