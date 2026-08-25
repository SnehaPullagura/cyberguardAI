import os
import logging
from typing import Any, Optional
from app.config import settings

logger = logging.getLogger(__name__)


class ModelArtifactStorage:
    """Manages model artifact directory structure, secure file path resolution, and artifact deletion."""

    def __init__(self, artifact_dir: Optional[str] = None):
        self.artifact_dir = artifact_dir or settings.ML_MODEL_DIR
        os.makedirs(self.artifact_dir, exist_ok=True)

    def get_artifact_path(self, filename: str) -> str:
        """Resolve safe absolute path for model artifact filename."""
        safe_filename = os.path.basename(filename)
        return os.path.join(self.artifact_dir, safe_filename)

    def artifact_exists(self, filename: str) -> bool:
        path = self.get_artifact_path(filename)
        return os.path.exists(path)

    def delete_artifact(self, filename: str) -> bool:
        path = self.get_artifact_path(filename)
        if os.path.exists(path):
            try:
                os.remove(path)
                logger.info(f"Deleted model artifact at {path}")
                return True
            except Exception as e:
                logger.warning(f"Failed to delete artifact {path}: {e}")
        return False


artifact_storage = ModelArtifactStorage()
