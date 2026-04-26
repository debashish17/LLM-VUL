"""
LLM-VUL Streamlit Interface - Integrated with src Pipeline
Uses Run 12 Model (304 features) for vulnerability detection
"""

import streamlit as st
import sys
from pathlib import Path
import tempfile
import shutil
import zipfile
import json
from datetime import datetime
from typing import List, Dict, Any
import pandas as pd

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parser.code_parser import CodeParser
from src.pipeline.combined_analyzer import CombinedAnalyzer
from src.pipeline.cwe_database import get_cwe_info, enrich_finding

try:
    from git import Repo
except ImportError:
    Repo = None


@st.cache_resource
def load_analyzer():
    """Load CombinedAnalyzer once per server session (heavy: CodeBERT + GraphCodeBERT + 4 models)."""
    return CombinedAnalyzer()


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def clone_github_repo(repo_url: str) -> Path:
    """Clone a GitHub repository to a temporary directory."""
    if Repo is None:
        raise Exception("GitPython is not installed. Please run: pip install GitPython")
    
    temp_dir = Path(tempfile.mkdtemp())
    repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
    clone_path = temp_dir / repo_name
    
    try:
        Repo.clone_from(repo_url, clone_path, depth=1)
        return clone_path
    except Exception as e:
        raise Exception(f"Failed to clone repository: {str(e)}")


def extract_c_cpp_files(directory: Path, max_files: int = 100) -> List[Path]:
    """Extract all C/C++ files from a directory."""
    extensions = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx'}
    files = []
    
    for ext in extensions:
        files.extend(directory.rglob(f'*{ext}'))
        if len(files) >= max_files:
            break
    
    return files[:max_files]


def parse_code_functions(file_paths: List[Path]) -> List[Dict[str, Any]]:
    """Parse C/C++ files and extract functions using tree-sitter CodeParser."""
    parser = CodeParser()
    functions = []
    
    for file_path in file_paths:
        try:
            # Detect language from file extension
            language = parser.detect_language(str(file_path))
            if not language:
                print(f"Skipping {file_path}: Could not detect language")
                continue
            
            # Parse the file using tree-sitter
            parse_result = parser.parse_file(str(file_path), language)
            
            if not parse_result.get('success'):
                print(f"Error parsing {file_path}: {parse_result.get('error')}")
                continue
            
            # Extract functions from parse result
            extracted_functions = parser.extract_functions(parse_result)
            
            for func_info in extracted_functions:
                func_code = func_info['code']
                func_name = func_info['name']
                
                # Filter out very small or very large functions
                if 10 < len(func_code) < 5000:
                    functions.append({
                        'function_name': func_name,
                        'code': func_code,
                        'file_path': str(file_path),
                        'language': language,
                        'line_number': func_info['start_line']
                    })
        
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            continue
    
    return functions


def detect_cwe_types(code: str) -> List[str]:
    """Detect CWE types in vulnerable code."""
    cwes = []
    
    # Pattern matching for common CWE patterns
    cwe_patterns = {
        'CWE-120': [r'strcpy|strcat|gets|scanf', 'Buffer Overflow'],
        'CWE-416': [r'use.*after.*free|UAF', 'Use-After-Free'],
        'CWE-476': [r'NULL|nullptr|!ptr', 'Null Pointer Dereference'],
        'CWE-190': [r'overflow|INT_MAX|UINT_MAX', 'Integer Overflow'],
        'CWE-835': [r'while.*1|for.*ever|infinite', 'Infinite Loop'],
    }
    
    for cwe_id, (pattern, name) in cwe_patterns.items():
        if any(p in code.lower() for p in pattern.split('|')):
            cwes.append(f"{cwe_id}: {name}")
    
    return cwes if cwes else ['CWE-Unknown']


def generate_report(results: List[Dict[str, Any]], file_paths: List[Path]) -> Dict[str, Any]:
    """Generate vulnerability report."""
    vulnerable_results = [r for r in results if r['vulnerable']]
    
    # Get threshold from results (either 'threshold' or 'ml_threshold')
    threshold = 0.308
    if results:
        threshold = results[0].get('threshold', results[0].get('ml_threshold', 0.308))
    
    return {
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'model_version': 'Run 12 - Production (Hybrid Static + ML)',
            'threshold': threshold,
            'total_files_analyzed': len(file_paths),
            'total_functions_analyzed': len(results)
        },
        'summary': {
            'total_functions': len(results),
            'vulnerable_functions': len(vulnerable_results),
            'safe_functions': len(results) - len(vulnerable_results),
            'vulnerability_rate': f"{len(vulnerable_results) / len(results) * 100:.1f}%" if results else "0%"
        },
        'results': results
    }



def display_detailed_result(result: Dict[str, Any], idx: int):
    """Display detailed vulnerability information from combined analysis."""
    col_a, col_b = st.columns([3, 2])

    with col_a:
        st.markdown("### 📍 Location")
        st.markdown(f"**File:** `{result.get('file_path', 'Unknown')}`")
        st.markdown(f"**Function:** `{result['function_name']}`")
        if result.get('line_number', 'Unknown') != 'Unknown':
            st.markdown(f"**Line:** {result['line_number']}")

        st.markdown("### 💻 Code Snippet")
        st.code(result.get('code_snippet', result.get('code', '')[:500]), language="cpp")

    with col_b:
        st.markdown("### 🎯 Classification")
        status_color = "🔴" if result['vulnerable'] else "🟢"
        st.markdown(f"**Status:** {status_color} **{result['binary_label']}**")

        st.markdown("**Static Confidence:**")
        sf = max(0.0, min(1.0, float(result['static_confidence'])))
        st.progress(sf)
        st.caption(f"{sf:.2%}")

        st.markdown("**ML Confidence:**")
        mlf = max(0.0, min(1.0, float(result['ml_confidence'])))
        st.progress(mlf)
        st.caption(f"{mlf:.2%}")

        if result['vulnerable']:
            severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
            severity = result.get('severity', 'UNKNOWN')
            st.markdown(f"**Severity:** {severity_emoji.get(severity, '⚪')} **{severity}**")

            src = result.get('detector_source', result.get('detector', 'Unknown'))
            if result.get('agreement'):
                st.success("✅ ML Confirmed")
            elif src == "Static Analysis":
                st.warning("⚠️ Static Only — not ML confirmed")
            else:
                st.info("🤖 ML Only")

    # Analysis details — split into Static Findings and ML Assessment
    st.markdown("### 📊 Analysis Details")
    col_static, col_ml = st.columns(2)

    with col_static:
        st.markdown("**🔎 Static Tool Findings:**")
        if result.get('static_findings'):
            findings_df = pd.DataFrame([
                {
                    'Tool': f.get('tool', 'unknown'),
                    'Message': f.get('message', ''),
                    'Severity': f.get('severity', 'LOW'),
                    'CWE': f.get('cwe', 'N/A')
                }
                for f in result['static_findings']
            ])
            st.dataframe(findings_df, width='stretch')
        else:
            st.caption("No static findings.")

        if result.get('cwe_types'):
            st.markdown("**CWE Types:**")
            for cwe in result['cwe_types']:
                st.markdown(f"- `{cwe}`")

    with col_ml:
        st.markdown("**🤖 ML Assessment (Run 12):**")
        st.markdown(f"- **Prediction:** {'Vulnerable 🔴' if result['ml_vulnerable'] else 'Safe 🟢'}")
        st.markdown("**Ensemble Model Scores:**")
        if result.get('ml_models'):
            scores_df = pd.DataFrame([
                {'Model': name, 'Score': f"{score:.2%}"}
                for name, score in result['ml_models'].items()
            ])
            st.dataframe(scores_df, width='stretch')
        else:
            st.caption("No model scores available.")

    


# ============================================================================
# PAGE SETUP
# ============================================================================

st.set_page_config(
    page_title="LLM-VUL - Vulnerability Detection",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'analyzer_loaded' not in st.session_state:
    st.session_state.analyzer_loaded = False
    st.session_state.analyzer = None
    st.session_state.results = None
    st.session_state.code_path = None
    st.session_state.file_count = 0

# Header
st.markdown('<div class="main-header">🔒 LLM-VUL</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">AI-Powered C/C++ Vulnerability Detection System</div>', unsafe_allow_html=True)
st.markdown("---")

# Sidebar - Model Info
with st.sidebar:
    st.header("📊 Model Information")
    st.markdown("""
    **Hybrid Vulnerability Detection**
    
    **Phase 1: Static Analysis**
    - CppCheck (memory safety)
    - Flawfinder (dangerous functions)
    - Semgrep (custom patterns)
    
    **Phase 2: ML Analysis (Run 12)**
    - F1 Score: 0.6143
    - Precision: 55.1%
    - Recall: 69.4%
    - ROC-AUC: 0.9060
    
    **Features (304 total):**
    - 240 Engineered Features
    - 32 CodeBERT Embeddings
    - 32 GraphCodeBERT Embeddings
    
    **Ensemble Models:**
    - XGBoost (Conservative + Aggressive)
    - LightGBM Balanced
    - CatBoost
    - Weighted Vote
    
    **Result Merging:**
    - Vulnerable if EITHER static OR ML finds issue
    - Uses HIGHEST confidence score
    - Shows which detector was more confident
    """)
    
    st.markdown("---")
    
    st.header("⚙️ Settings")
    confidence_threshold = st.slider(
        "Confidence Threshold",
        min_value=0.0,
        max_value=1.0,
        value=0.308,
        step=0.001,
        help="Predictions above this threshold are considered vulnerable"
    )
    
    max_files = st.number_input(
        "Max Files to Analyze",
        min_value=1,
        max_value=1000,
        value=100,
        help="Limit number of files to process"
    )

# Main content
tab1, tab2 = st.tabs(["🔍 Analyze Code", "📄 About"])

with tab1:
    st.header("Input Source")
    
    input_method = st.radio(
        "Choose input method:",
        ["GitHub Repository", "Upload ZIP File"],
        horizontal=True
    )
    
    if input_method == "Upload ZIP File":
        uploaded_file = st.file_uploader(
            "Upload a ZIP file containing C/C++ code",
            type=['zip'],
            help="ZIP file should contain .c, .cpp, .h, .hpp files"
        )
        
        if uploaded_file:
            file_id = f"{uploaded_file.name}_{uploaded_file.size}"
            if st.session_state.get('last_file_id') != file_id:
                with st.spinner("Extracting ZIP file..."):
                    temp_dir = tempfile.mkdtemp()
                    zip_path = Path(temp_dir) / uploaded_file.name
                    
                    with open(zip_path, 'wb') as f:
                        f.write(uploaded_file.getbuffer())
                    
                    extract_dir = Path(temp_dir) / "extracted"
                    extract_dir.mkdir(exist_ok=True)
                    
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        zip_ref.extractall(extract_dir)
                    
                    st.session_state.code_path = extract_dir
                    st.session_state.last_file_id = file_id
                    
                    c_cpp_files = extract_c_cpp_files(extract_dir, max_files=10000)
                    st.session_state.file_count = len(c_cpp_files)
                
                st.success(f"✅ Extracted {st.session_state.file_count} C/C++ files")
    
    else:  # GitHub Repository
        repo_url = st.text_input(
            "GitHub Repository URL",
            placeholder="https://github.com/username/repo",
            help="Enter the full GitHub repository URL"
        )
        
        if repo_url and st.button("Clone Repository"):
            with st.spinner("Cloning repository..."):
                try:
                    cloned_path = clone_github_repo(repo_url)
                    st.session_state.code_path = cloned_path
                    
                    c_cpp_files = extract_c_cpp_files(cloned_path, max_files=10000)
                    st.session_state.file_count = len(c_cpp_files)
                    
                    st.success(f"✅ Cloned successfully! Found {st.session_state.file_count} C/C++ files")
                except Exception as e:
                    st.error(f"❌ Error cloning repository: {str(e)}")
                    st.session_state.code_path = None
        
        elif st.session_state.code_path:
            st.info(f"✅ Repository ready: {st.session_state.file_count} C/C++ files found")
    
    # Analyze button
    if st.session_state.code_path:
        st.markdown("---")
        
        if st.button("🚀 Analyze for Vulnerabilities", type="primary"):
            st.session_state.run_analysis = True
            
        if st.session_state.get('run_analysis', False):
            code_path = st.session_state.code_path
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            try:
                # Step 1: Load analyzer
                status_text.text("Loading vulnerability analyzer (Static + ML)...")
                progress_bar.progress(10)

                if not st.session_state.analyzer_loaded:
                    analyzer = load_analyzer()
                    st.session_state.analyzer = analyzer
                    st.session_state.analyzer_loaded = True

                # Step 2: Extract C/C++ files
                status_text.text("Scanning for C/C++ files...")
                progress_bar.progress(20)
                c_cpp_files = extract_c_cpp_files(code_path, max_files=max_files)

                if not c_cpp_files:
                    st.error("❌ No C/C++ files found!")
                else:
                    st.info(f"📁 Found {len(c_cpp_files)} C/C++ files")
                    progress_bar.progress(30)

                    # Step 3: Parse and extract functions
                    status_text.text("Parsing code and extracting functions...")
                    progress_bar.progress(40)
                    functions = parse_code_functions(c_cpp_files)

                    if not functions:
                        st.warning("⚠️ No functions found in the code!")
                    else:
                        st.info(f"🔧 Extracted {len(functions)} functions")
                        progress_bar.progress(50)

                        # Step 4: Combined Analysis (Static + ML)
                        status_text.text("Running vulnerability analysis (Static Analysis + ML Model)...")
                        progress_bar.progress(60)
                        results = st.session_state.analyzer.analyze(
                            functions,
                            ml_threshold=confidence_threshold
                        )
                        st.session_state.results = results
                        st.session_state.c_cpp_files = c_cpp_files
                        st.session_state.functions = functions
                        progress_bar.progress(80)

                        # Step 5: Generate report
                        status_text.text("Generating report...")
                        progress_bar.progress(90)
                        report = generate_report(results, c_cpp_files)
                        st.session_state.report = report
                        progress_bar.progress(100)
                        status_text.text("✅ Analysis complete!")

            except Exception as e:
                st.error(f"❌ Error during analysis: {str(e)}")
                import traceback
                traceback.print_exc()
            finally:
                st.session_state.run_analysis = False
        
    # Render results if available
    if st.session_state.results is not None:
        try:
            results = st.session_state.results
            c_cpp_files = getattr(st.session_state, 'c_cpp_files', [])
            functions = getattr(st.session_state, 'functions', [])
            report = getattr(st.session_state, 'report', "")
            
            # Display results
            print("[DEBUG] Starting results display...")
            st.markdown("---")
            st.header("📊 Vulnerability Analysis Results")
            print(f"[DEBUG] Results count: {len(results)}")
            
            # Summary metrics
            print("[DEBUG] Creating summary metrics...")
            vuln_count = sum(1 for r in results if r['vulnerable'])
            safe_count = len(results) - vuln_count
            critical_count = sum(1 for r in results if r.get('severity') == 'CRITICAL')
            high_count = sum(1 for r in results if r.get('severity') == 'HIGH')
            medium_count = sum(1 for r in results if r.get('severity') == 'MEDIUM')
            low_count = sum(1 for r in results if r.get('severity') == 'LOW')
            confirmed_count = sum(1 for r in results if r.get('agreement'))

            col1, col2, col3, col4, col5 = st.columns(5)
            with col1:
                st.metric("Total Functions", len(results))
            with col2:
                st.metric("Vulnerable", vuln_count,
                          delta=f"{vuln_count/len(results)*100:.1f}%" if results else "0%",
                          delta_color="inverse")
            with col3:
                st.metric("Both Confirmed", confirmed_count,
                          help="Flagged by BOTH static analysis AND ML model")
            with col4:
                avg_ml_conf = sum(r['ml_confidence'] for r in results if r['vulnerable']) / max(vuln_count, 1)
                st.metric("Avg ML Confidence", f"{avg_ml_conf:.1%}")
            with col5:
                st.metric("Safe", safe_count)

            # Severity distribution
            print("[DEBUG] Rendering severity distribution...")
            if vuln_count > 0:
                st.markdown("**Severity Distribution:**")
                sev_cols = st.columns(4)
                sev_data = [
                    ("CRITICAL", critical_count, "🔴"),
                    ("HIGH", high_count, "🟠"),
                    ("MEDIUM", medium_count, "🟡"),
                    ("LOW", low_count, "🟢"),
                ]
                for col, (label, count, emoji) in zip(sev_cols, sev_data):
                    with col:
                        st.metric(f"{emoji} {label}", count)

                chart_data = pd.DataFrame({
                    'Severity': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                    'Count': [critical_count, high_count, medium_count, low_count]
                })
                # st.bar_chart(chart_data.set_index('Severity'))
                st.bar_chart(chart_data, x="Severity", y="Count")
            
            st.markdown("---")
            
            # Results tabs
            print("[DEBUG] Rendering tabs...")
            st.subheader("📋 Analysis Results")
            
            tab_vuln, tab_safe, tab_all = st.tabs(["🚨 Vulnerable", "✅ Safe", "📊 All Functions"])
            
            with tab_vuln:
                vuln_results = [r for r in results if r['vulnerable']]
                if vuln_results:
                    st.info(f"🚨 Found {len(vuln_results)} vulnerable functions")
                    vuln_results.sort(key=lambda x: x['confidence'], reverse=True)
                    
                    if len(vuln_results) > 20:
                        st.warning("⚠️ Displaying top 20 most confident vulnerabilities to avoid browser crash. Use the 'All Functions' tab to view and filter all results.")

                    for idx, result in enumerate(vuln_results[:20], 1):
                        src = result.get('detector_source', 'Unknown')
                        if src == "Both (Static + ML)":
                            badge = "✅ Both Confirmed"
                        elif src == "ML Model":
                            badge = "🤖 ML Only"
                        elif src == "Static Analysis":
                            badge = "🔎 Static Only"
                        else:
                            badge = src
                        sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(result.get('severity', 'UNKNOWN'), "⚪")
                        with st.expander(
                            f"#{idx} · {result['function_name']} · "
                            f"{sev_emoji} {result.get('severity', 'UNKNOWN')} [{badge}] · "
                            f"Static: {result['static_confidence']:.1%} | ML: {result['ml_confidence']:.1%}",
                            expanded=(idx <= 3)
                        ):
                            try:
                                display_detailed_result(result, idx)
                            except Exception as render_err:
                                st.error(f"Could not render details for `{result.get('function_name', 'unknown')}`: {render_err}")
                else:
                    st.success("✅ No vulnerabilities detected!")
            
            with tab_safe:
                safe_results = [r for r in results if not r['vulnerable']]
                if safe_results:
                    st.info(f"Found {len(safe_results)} safe functions")
                    safe_results.sort(key=lambda x: x['confidence'])
                    
                    st.warning("⚠️ Displaying 5 top safe functions to avoid browser crash.")
                    for idx, result in enumerate(safe_results[:5], 1):
                        with st.expander(f"#{idx} · {result['function_name']}", expanded=False):
                            try:
                                display_detailed_result(result, idx)
                            except Exception as render_err:
                                st.error(f"Could not render details for `{result.get('function_name', 'unknown')}`: {render_err}")
            
            with tab_all:
                filter_col1, filter_col2 = st.columns(2)
                with filter_col1:
                    status_filter = st.selectbox(
                        "Filter by Status",
                        ["All", "Vulnerable", "Safe"],
                        key="status_filter"
                    )
                with filter_col2:
                    severity_filter = st.selectbox(
                        "Filter by Severity",
                        ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "N/A"],
                        key="severity_filter"
                    )

                filtered = results
                if status_filter != "All":
                    filtered = [r for r in filtered if r['binary_label'] == status_filter]
                if severity_filter != "All":
                    filtered = [r for r in filtered if r.get('severity') == severity_filter]

                filtered_sorted = sorted(filtered, key=lambda r: (not r['vulnerable'], -r['confidence']))

                all_df = pd.DataFrame([
                    {
                        'Function': r['function_name'],
                        'File': Path(r['file_path']).name,
                        'Status': r['binary_label'],
                        'Detector': r.get('detector_source', 'Unknown'),
                        'Severity': r.get('severity', 'N/A'),
                        'Static Conf': round(r['static_confidence'], 4),
                        'ML Conf': round(r['ml_confidence'], 4),
                        'Agreement': '✅' if r.get('agreement') else '—'
                    }
                    for r in filtered_sorted
                ])

                st.dataframe(
                    all_df,
                    width='stretch',
                    column_config={
                        'Static Conf': st.column_config.ProgressColumn(
                            'Static Conf',
                            min_value=0,
                            max_value=1,
                            format="%f"
                        ),
                        'ML Conf': st.column_config.ProgressColumn(
                            'ML Conf',
                            min_value=0,
                            max_value=1,
                            format="%f"
                        ),
                        }
                    )
                st.caption(f"Showing {len(filtered_sorted)} of {len(results)} functions")
            
            # Download report
            st.markdown("---")
            st.header("📥 Download Report")
            
            try:
                report_json = json.dumps(report, indent=2)
                st.download_button(
                    label="Download JSON Report",
                    data=report_json,
                    file_name=f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
            except TypeError as je:
                st.warning(f"⚠️ Report serialization issue: {str(je)}")
                st.info("Report data may contain non-serializable objects, but analysis is complete.")
                
        except Exception as e:
            st.error(f"❌ Error during analysis rendering: {str(e)}")
            import traceback
            st.error(traceback.format_exc())

with tab2:
    st.header("About LLM-VUL")
    st.markdown("""
    **LLM-VUL** is a hybrid AI-powered vulnerability detection system for C/C++ code combining static analysis and machine learning.
    
    ### Features
    - ✅ Upload ZIP files or clone GitHub repositories
    - ✅ Automatic function extraction using tree-sitter AST parser
    - ✅ **Dual-Phase Detection:**
      - Phase 1: Fast static analysis (CppCheck, Flawfinder, Semgrep)
      - Phase 2: Deep ML analysis (304-feature Run 12 ensemble)
    - ✅ Result merging (takes union of both detectors)
    - ✅ Confidence-based severity classification
    - ✅ CWE type detection and source attribution
    - ✅ Detailed analysis transparency (shows both detectors)
    - ✅ JSON report generation
    
    ### Detection Pipeline
    
    **Phase 1: Static Analysis (Fast)**
    - CppCheck: Memory safety violations, null pointers, buffer overflows
    - Flawfinder: Dangerous functions (strcpy, gets, sprintf, etc.)
    - Semgrep: Custom regex-based vulnerability patterns
    
    **Phase 2: ML Analysis (Accurate)**
    - 240 Engineered Features (complexity, metrics, patterns)
    - 32 CodeBERT Embeddings (semantic code understanding)
    - 32 GraphCodeBERT Embeddings (graph-aware semantics)
    - 4-Model Ensemble (XGBoost, LightGBM, CatBoost)
    
    **Result Merging Strategy:**
    - Vulnerable if EITHER detector finds an issue (Union)
    - Uses HIGHEST confidence from both detectors
    - Attributes result to most confident source
    - Combines CWE types from both detectors
    
    ### Performance (Phase 2: Run 12 ML)
    - F1 Score: 0.6143
    - Precision: 55.1%
    - Recall: 69.4%
    - ROC-AUC: 0.9060
    
    ### When to Use
    - **Static Analysis alone**: Ultra-fast, high false positive rate
    - **ML alone**: Slower, more accurate, misses obvious issues
    - **Both combined**: Balanced speed/accuracy, comprehensive coverage
    """)
