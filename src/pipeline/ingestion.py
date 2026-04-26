"""
Code Ingestion Module
Handles ZIP extraction and function-level code parsing via tree-sitter.
"""
import zipfile
import tempfile
import shutil
import os
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path

from src.parser.code_parser import CodeParser

logger = logging.getLogger(__name__)

# C/C++ file extensions we handle
C_CPP_EXTENSIONS = {'.c', '.h', '.cpp', '.hpp', '.cc', '.cxx', '.hh', '.hxx'}

# Extension → language mapping
EXTENSION_TO_LANG = {
    '.c': 'c',
    '.h': 'c',
    '.cpp': 'cpp',
    '.hpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.hh': 'cpp',
    '.hxx': 'cpp',
}

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB

# Directories to skip during extraction walk
SKIP_DIRS = {
    '.git', '__pycache__', 'node_modules', 'build', 'bin',
    'obj', '.svn', '.hg', 'CMakeFiles', '.vs',
}


@dataclass
class SourceFile:
    """A single source file extracted from the ZIP."""
    abs_path: str
    rel_path: str
    language: str       # 'c' or 'cpp'
    content: str
    size: int


@dataclass
class FunctionUnit:
    """A single function extracted from a source file."""
    file_rel_path: str
    file_abs_path: str
    function_name: str
    code: str
    start_line: int
    end_line: int
    language: str

    @property
    def uid(self) -> str:
        """Unique identifier: path::name::start_line"""
        return f"{self.file_rel_path}::{self.function_name}::{self.start_line}"


@dataclass
class IngestionResult:
    """Result of ZIP ingestion."""
    temp_dir: str
    source_zip: str
    files: List[SourceFile]
    functions: List[FunctionUnit]
    skipped_files: List[Dict]          # [{path, reason}, ...]

    def cleanup(self):
        """Remove the temporary directory."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            logger.info(f"Cleaned up temp directory: {self.temp_dir}")


class CodeIngestion:
    """Extracts a ZIP archive, discovers C/C++ files, and parses them into functions."""

    def __init__(self):
        self.parser = CodeParser()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def ingest_zip(self, zip_path: str) -> IngestionResult:
        """
        Extract *zip_path*, discover C/C++ source files, parse each with
        tree-sitter, and return extracted functions.

        Args:
            zip_path: Path to the ZIP file.

        Returns:
            IngestionResult containing source files, functions, and metadata.
        """
        zip_path = os.path.abspath(zip_path)
        if not os.path.exists(zip_path):
            raise FileNotFoundError(f"ZIP file not found: {zip_path}")
        if not zipfile.is_zipfile(zip_path):
            raise ValueError(f"Not a valid ZIP file: {zip_path}")

        # Extract to a fresh temp directory
        temp_dir = tempfile.mkdtemp(prefix="vulnscan_")
        logger.info(f"Extracting {zip_path} → {temp_dir}")

        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # Safety: skip entries with absolute paths or '..'
                safe_members = [
                    m for m in zf.infolist()
                    if not m.filename.startswith('/') and '..' not in m.filename
                ]
                zf.extractall(temp_dir, members=safe_members)
        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Failed to extract ZIP: {e}")

        # Walk the extracted tree and collect C/C++ source files
        files: List[SourceFile] = []
        skipped: List[Dict] = []

        for root, dirs, filenames in os.walk(temp_dir):
            # Prune directories we never want to descend into
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith('.')]

            for fname in filenames:
                abs_path = os.path.join(root, fname)
                rel_path = os.path.relpath(abs_path, temp_dir)
                ext = os.path.splitext(fname)[1].lower()

                if ext not in C_CPP_EXTENSIONS:
                    continue

                # Skip symlinks
                if os.path.islink(abs_path):
                    skipped.append({'path': rel_path, 'reason': 'symlink'})
                    continue

                # Skip oversized files
                file_size = os.path.getsize(abs_path)
                if file_size > MAX_FILE_SIZE:
                    skipped.append({'path': rel_path, 'reason': f'too large ({file_size:,} bytes)'})
                    logger.warning(f"Skipping oversized file: {rel_path} ({file_size:,} bytes)")
                    continue

                # Skip binary / non-UTF-8 files
                try:
                    with open(abs_path, 'r', encoding='utf-8', errors='strict') as f:
                        content = f.read()
                except UnicodeDecodeError:
                    # Retry with latin-1 (covers virtually all byte sequences)
                    try:
                        with open(abs_path, 'r', encoding='latin-1') as f:
                            content = f.read()
                    except Exception:
                        skipped.append({'path': rel_path, 'reason': 'binary / unreadable'})
                        continue

                language = EXTENSION_TO_LANG.get(ext, 'c')
                files.append(SourceFile(
                    abs_path=abs_path,
                    rel_path=rel_path,
                    language=language,
                    content=content,
                    size=file_size,
                ))

        logger.info(f"Found {len(files)} C/C++ source file(s), skipped {len(skipped)}")

        # Extract functions from every source file
        functions: List[FunctionUnit] = []
        for src_file in files:
            functions.extend(self._extract_functions(src_file))

        logger.info(f"Extracted {len(functions)} function(s) from {len(files)} file(s)")

        return IngestionResult(
            temp_dir=temp_dir,
            source_zip=os.path.basename(zip_path),
            files=files,
            functions=functions,
            skipped_files=skipped,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _extract_functions(self, source_file: SourceFile) -> List[FunctionUnit]:
        """Parse a single source file and extract its function definitions."""
        parse_result = self.parser.parse_code(
            source_file.content,
            source_file.language,
            filepath=source_file.abs_path,
        )

        # Fallback: if C parsing fails, try C++
        if not parse_result.get('success') and source_file.language == 'c':
            parse_result = self.parser.parse_code(
                source_file.content, 'cpp', filepath=source_file.abs_path
            )

        if not parse_result.get('success'):
            logger.warning(
                f"Failed to parse {source_file.rel_path}: "
                f"{parse_result.get('error', 'unknown error')}"
            )
            return []

        raw_functions = self.parser.extract_functions(parse_result)

        units: List[FunctionUnit] = []
        for func in raw_functions:
            units.append(FunctionUnit(
                file_rel_path=source_file.rel_path,
                file_abs_path=source_file.abs_path,
                function_name=func['name'],
                code=func['code'],
                start_line=func['start_line'],
                end_line=func['end_line'],
                language=source_file.language,
            ))

        return units
