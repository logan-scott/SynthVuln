import logging
import yaml
from typing import Dict, Any


def setup_logging(log_file: str, logger_name: str = '__main__', log_level: int = logging.INFO) -> logging.Logger:
    """Setup logging configuration for generators.
    
    Args:
        log_file: Path to the log file
        logger_name: Name for the logger (defaults to '__main__')
        log_level: Logging level (defaults to INFO)
        
    Returns:
        Configured logger instance
    """
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file, mode='a')
        ]
    )
    return logging.getLogger(logger_name)


def load_config(config_file: str, logger: logging.Logger | None = None, use_fallback: bool = True) -> Dict[str, Any]:
    """Load configuration from YAML file with comprehensive error handling.
    
    Args:
        config_file: Path to YAML configuration file
        logger: Logger instance for error reporting (optional)
        use_fallback: Whether to use fallback configuration on errors
        
    Returns:
        Dictionary containing configuration settings
        
    Raises:
        Uses fallback configuration or empty dict if file cannot be loaded
    """
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            if logger:
                logger.info(f"Successfully loaded configuration from {config_file}")
            return config
    except FileNotFoundError:
        message = f"Configuration file {config_file} not found"
        if logger:
            if use_fallback:
                logger.warning(f"{message}, using fallback configuration")
            else:
                logger.warning(f"{message}. Using defaults.")
        else:
            print(f"Warning: Config file {config_file} not found. Using defaults.")
        return get_fallback_config() if use_fallback else {}
    except PermissionError:
        message = f"Permission denied accessing {config_file}"
        if logger:
            if use_fallback:
                logger.error(f"{message}, using fallback configuration")
            else:
                logger.error(f"{message}")
        else:
            print(f"Error loading config: {message}")
        return get_fallback_config() if use_fallback else {}
    except yaml.YAMLError as e:
        message = f"Invalid YAML in {config_file}: {e}"
        if logger:
            if use_fallback:
                logger.error(f"{message}, using fallback configuration")
            else:
                logger.error(f"{message}")
        else:
            print(f"Error loading config: {e}")
        return get_fallback_config() if use_fallback else {}
    except Exception as e:
        message = f"Unexpected error loading config file {config_file}: {e}"
        if logger:
            if use_fallback:
                logger.error(f"{message}, using fallback configuration")
            else:
                logger.error(f"{message}")
        else:
            print(f"Error loading config: {e}")
        return get_fallback_config() if use_fallback else {}


def get_fallback_config() -> Dict[str, Any]:
    """Get fallback configuration when config file cannot be loaded.
    
    Returns:
        Dictionary containing minimal fallback configuration
    """
    return {
        'asset_config': {
            'asset_types': ['Server', 'Desktop', 'Mobile device', 'Network device'],
            'locations': ['Internal', 'Remote', 'Data center', 'Cloud']
        },
        'findings_config': {
            'detection_tools': ['Nessus', 'Qualys', 'OpenVAS', 'Nexpose', 'Tenable.io'],
            'severity_weights': {'CRITICAL': 5, 'HIGH': 15, 'MEDIUM': 35, 'LOW': 45}
        },
        'performance_config': {
            'default_count': 10,
            'batch_size': 1000,
            'progress_report_interval': 100
        },
        'default_paths': {
            'asset_output': 'data/raw/assets.json',
            'findings_output': 'data/raw/findings.json'
        }
    }