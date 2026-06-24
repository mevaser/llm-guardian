import os
from pathlib import Path
from unittest.mock import patch
from llm_guardian.env import load_local_env

def test_load_local_env_from_repo_root():
    """Verify that .env is loaded from the repository root, without overriding."""
    fake_env_path = Path("/fake/repo/root/.env")
    
    with patch("llm_guardian.env.Path") as MockPath:
        # Setup the mock so that Path(__file__).resolve().parents[2] returns /fake/repo/root
        mock_file_path = MockPath.return_value
        mock_file_path.resolve.return_value.parents = [None, None, Path("/fake/repo/root")]
        
        with patch("llm_guardian.env.load_dotenv") as mock_load_dotenv:
            # We must also mock exists() to return True on the appended Path
            with patch.object(Path, "exists", return_value=True):
                load_local_env()
                
                # Verify that load_dotenv was called with the correct path
                # Since we return a real Path("/fake/repo/root") from the mock, 
                # repo_root / ".env" will be Path("/fake/repo/root/.env")
                mock_load_dotenv.assert_called_once_with(
                    dotenv_path=Path("/fake/repo/root/.env"), 
                    override=False
                )

def test_missing_env_does_not_crash():
    """Verify that a missing .env file does not cause an error."""
    with patch("llm_guardian.env.Path") as MockPath:
        mock_file_path = MockPath.return_value
        mock_file_path.resolve.return_value.parents = [None, None, Path("/fake/repo/root")]
        
        with patch("llm_guardian.env.load_dotenv") as mock_load_dotenv:
            # exists() returns False
            with patch.object(Path, "exists", return_value=False):
                load_local_env()
                
                # Should not have called load_dotenv
                mock_load_dotenv.assert_not_called()
