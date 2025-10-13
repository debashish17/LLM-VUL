# LLM-VUL

A toolkit for vulnerability dataset normalization, analysis, and model training.

## Structure
- `data/` — raw and processed datasets
- `normalized/` — unified JSONL datasets
- `scripts/` — normalization and utility scripts
- `models/` — model checkpoints
- `notebooks/` — data exploration and training

## Quick Start
```bash
pip install -r requirements.txt
python scripts/prepdata.py
python prep_zenodo_all.py
```

## Notebooks
- `notebooks/01_data_exploration.ipynb` — Explore and visualize datasets
