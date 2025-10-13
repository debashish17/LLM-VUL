"""
Code Parser Module - Production Ready
Tree-sitter based parser for multiple languages
"""
import tree_sitter_language_pack as ts_pack
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class CodeParser:
    """Universal code parser supporting multiple languages"""
    
    SUPPORTED_LANGUAGES = {
        'python', 'java', 'c', 'cpp', 'php', 
        'javascript', 'go', 'rust', 'ruby', 'kotlin', 'swift'
    }
    
    EXTENSION_MAP = {
        '.py': 'python',
        '.java': 'java',
        '.c': 'c',
        '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.h': 'cpp', '.hpp': 'cpp',
        '.php': 'php',
        '.js': 'javascript', '.jsx': 'javascript', '.ts': 'javascript', '.tsx': 'javascript',
        '.go': 'go',
        '.rs': 'rust',
        '.rb': 'ruby',
        '.kt': 'kotlin', '.kts': 'kotlin',
        '.swift': 'swift',
    }
    
    def __init__(self):
        """Initialize parsers for all supported languages"""
        self.parsers = {}
        self._initialize_parsers()
    
    def _initialize_parsers(self):
        """Load parsers for supported languages"""
        for lang in self.SUPPORTED_LANGUAGES:
            try:
                self.parsers[lang] = ts_pack.get_parser(lang)
                logger.info(f"Loaded parser for {lang}")
            except Exception as e:
                logger.warning(f"Could not load parser for {lang}: {e}")
    
    def detect_language(self, filepath: str) -> Optional[str]:
        """
        Detect programming language from file extension
        
        Args:
            filepath: Path to source file
            
        Returns:
            Language identifier or None
        """
        ext = Path(filepath).suffix.lower()
        return self.EXTENSION_MAP.get(ext)
    
    def parse_file(self, filepath: str, language: Optional[str] = None) -> Dict:
        """
        Parse a source code file
        
        Args:
            filepath: Path to file
            language: Language hint (auto-detected if None)
            
        Returns:
            Parse result dictionary
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            if not language:
                language = self.detect_language(filepath)
            
            if not language:
                return {
                    'success': False,
                    'error': 'Could not detect language',
                    'filepath': filepath
                }
            
            return self.parse_code(code, language, filepath=filepath)
        
        except Exception as e:
            logger.error(f"Error parsing file {filepath}: {e}")
            return {
                'success': False,
                'error': str(e),
                'filepath': filepath
            }
    
    def parse_code(self, code: str, language: str, filepath: str = None) -> Dict:
        """
        Parse source code string
        
        Args:
            code: Source code string
            language: Programming language
            filepath: Optional file path for context
            
        Returns:
            Parse result with AST and metadata
        """
        parser = self.parsers.get(language)
        
        if not parser:
            return {
                'success': False,
                'error': f'Unsupported language: {language}',
                'language': language
            }
        
        try:
            tree = parser.parse(bytes(code, 'utf8'))
            
            return {
                'success': True,
                'tree': tree,
                'root_node': tree.root_node,
                'language': language,
                'filepath': filepath,
                'code': code
            }
        except Exception as e:
            logger.error(f"Parse error: {e}")
            return {
                'success': False,
                'error': str(e),
                'language': language
            }
    
    def extract_functions(self, parse_result: Dict) -> List[Dict]:
        """
        Extract all function definitions from parsed code
        
        Args:
            parse_result: Result from parse_code()
            
        Returns:
            List of function information dictionaries
        """
        if not parse_result.get('success'):
            return []
        
        tree = parse_result['tree']
        code = parse_result['code']
        functions = []
        
        # Node types that represent functions in different languages
        function_types = {
            'function_definition',      # Python
            'function_declaration',     # C/C++
            'method_declaration',       # Java
            'method_definition',        # C++
            'function_item',            # Rust
            'function_declaration',     # Go
            'arrow_function',           # JavaScript
            'function_expression',      # JavaScript
        }
        
        def traverse(node):
            if node.type in function_types:
                func_code = code[node.start_byte:node.end_byte]
                functions.append({
                    'name': self._get_function_name(node, code),
                    'code': func_code,
                    'start_line': node.start_point[0] + 1,  # 1-indexed
                    'end_line': node.end_point[0] + 1,
                    'start_byte': node.start_byte,
                    'end_byte': node.end_byte,
                    'type': node.type
                })
            
            for child in node.children:
                traverse(child)
        
        traverse(tree.root_node)
        return functions
    
    def _get_function_name(self, node, code: str) -> str:
        """Extract function name from AST node"""
        # Look for identifier child nodes
        for child in node.children:
            if child.type == 'identifier':
                return code[child.start_byte:child.end_byte]
        
        # Fallback: look deeper
        for child in node.children:
            for grandchild in child.children:
                if grandchild.type == 'identifier':
                    return code[grandchild.start_byte:grandchild.end_byte]
        
        return "anonymous"
    
    def get_code_metrics(self, code: str, language: str) -> Dict:
        """
        Calculate basic code metrics
        
        Args:
            code: Source code string
            language: Programming language
            
        Returns:
            Dictionary of metrics
        """
        lines = code.split('\n')
        non_empty = [l for l in lines if l.strip()]
        
        return {
            'language': language,
            'total_lines': len(lines),
            'non_empty_lines': len(non_empty),
            'char_count': len(code),
            'avg_line_length': sum(len(l) for l in lines) / len(lines) if lines else 0
        }
    
    def get_supported_languages(self) -> List[str]:
        """Get list of supported languages"""
        return list(self.parsers.keys())


# Singleton instance
_parser_instance = None

def get_parser() -> CodeParser:
    """Get or create global parser instance"""
    global _parser_instance
    if _parser_instance is None:
        _parser_instance = CodeParser()
    return _parser_instance


# CLI test
if __name__ == "__main__":
    parser = CodeParser()
    
    print(f"Supported languages: {', '.join(parser.get_supported_languages())}")
    
    # Test code
    test_code = """
def unsafe_query(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return execute(query)

def safe_query(user_input):
    query = "SELECT * FROM users WHERE name = ?"
    return execute(query, (user_input,))
"""
    
    result = parser.parse_code(test_code, 'python')
    print(f"\nParse successful: {result['success']}")
    
    functions = parser.extract_functions(result)
    print(f"Found {len(functions)} functions:")
    for func in functions:
        print(f"  - {func['name']} (lines {func['start_line']}-{func['end_line']})")
    
    metrics = parser.get_code_metrics(test_code, 'python')
    print(f"\nMetrics:")
    for key, value in metrics.items():
        print(f"  {key}: {value}")