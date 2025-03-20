"""
Main entry point for SecretService
"""
import logging
from ui import SecretServiceUI
from pathlib import Path

def setup_logging():
    """Setup logging configuration"""
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'secretservice.log'),
            logging.StreamHandler()
        ]
    )

def main():
    """Main entry point"""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        app = SecretServiceUI()
        app.run()
    except Exception as e:
        logger.error(f"Application failed to start: {e}", exc_info=True)
        raise

if __name__ == '__main__':
    main() 