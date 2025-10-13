from setuptools import setup, find_packages

setup(
    name='llm_vul',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'pandas',
        'scikit-learn',
        'matplotlib',
        'seaborn',
        'jupyter',
    ],
    description='Vulnerability dataset normalization and analysis toolkit',
    author='Your Name',
)