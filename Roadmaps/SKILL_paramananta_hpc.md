# SKILL: Paramananta HPC — SLURM Operations Guide

> IIT Gandhinagar's supercomputer. SSH: `suhani@paramananta.iitgn.ac.in -p 4422`
> Read this whenever running batch jobs or debugging SLURM issues.

---

## Directory Layout

```
~/Workspace/
├── cyner_src/          # CyNER model code
├── parse/parse/        # Docling PDF parser (local copy)
└── slurm/              # SLURM submission scripts

/scratch/suhani/cyner_project/
├── data/
│   ├── cve_normalized.jsonl    # 323,647 CVE records
│   └── pdfs/                   # Parsed PDF JSONs
├── output/
│   ├── cve_shards/             # Per-shard NER output
│   └── pdfs/                   # Per-PDF NER output
├── logs/               # SLURM stdout/stderr
├── models/             # Downloaded model weights
└── code/               # ner_worker.py + SLURM scripts
```

---

## Environment Setup

```bash
# Connect
ssh suhani@paramananta.iitgn.ac.in -p 4422

# Activate environment
conda activate <your_env_name>   # check with: conda env list

# Verify key packages
python -c "import cyner, nltk, torch; print('all ok')"

# nltk corpora (fix if missing)
python -c "import nltk; nltk.download('punkt'); nltk.download('punkt_tab')"
```

---

## SLURM Quick Reference

```bash
# Submit job
sbatch script.sh

# Check status
squeue -u suhani

# Cancel job
scancel <JOBID>

# Cancel all your jobs
scancel -u suhani

# See finished job info
sacct -j <JOBID> --format=JobID,State,ExitCode,Elapsed,MaxRSS

# Interactive GPU session (for debugging)
srun --gpus=1 --mem=16G --time=01:00:00 --pty bash
```

---

## CVE Array Job Script Template

```bash
#!/bin/bash
#SBATCH --job-name=ner_cves
#SBATCH --array=0-49           # 50 shards
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --gpus=1
#SBATCH --mem=16G
#SBATCH --time=04:00:00
#SBATCH --output=/scratch/suhani/cyner_project/logs/ner_cve_%a.log
#SBATCH --error=/scratch/suhani/cyner_project/logs/ner_cve_%a.err

source ~/.bashrc
conda activate <your_env>

SHARD_ID=$(printf "%03d" $SLURM_ARRAY_TASK_ID)
INPUT=/scratch/suhani/cyner_project/data/cve_normalized.jsonl
OUTPUT=/scratch/suhani/cyner_project/output/cve_shards/shard_${SHARD_ID}_entities.jsonl
MODEL=/scratch/suhani/cyner_project/models/cyner

python /scratch/suhani/cyner_project/code/ner_worker.py \
    --mode cve \
    --input $INPUT \
    --output $OUTPUT \
    --shard-id $SLURM_ARRAY_TASK_ID \
    --total-shards 50 \
    --model-path $MODEL \
    --batch-size 32
```

---

## PDF NER Job Script Template

```bash
#!/bin/bash
#SBATCH --job-name=ner_pdfs
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --gpus=1
#SBATCH --mem=8G
#SBATCH --time=01:00:00
#SBATCH --output=/scratch/suhani/cyner_project/logs/ner_pdfs.log

source ~/.bashrc
conda activate <your_env>

python /scratch/suhani/cyner_project/code/ner_worker.py \
    --mode pdf \
    --input /scratch/suhani/cyner_project/data/pdfs/ \
    --output /scratch/suhani/cyner_project/output/pdfs/ \
    --model-path /scratch/suhani/cyner_project/models/cyner
```

---

## Merge Shards Script

```bash
#!/bin/bash
#SBATCH --job-name=merge_shards
#SBATCH --ntasks=1
#SBATCH --mem=8G
#SBATCH --time=00:30:00
#SBATCH --output=/scratch/suhani/cyner_project/logs/merge.log
#SBATCH --dependency=afterok:<CVE_ARRAY_JOBID>   # runs after array completes

OUTPUT_DIR=/scratch/suhani/cyner_project/output/cve_shards
FINAL=/scratch/suhani/cyner_project/output/cve_entities_all.jsonl

cat $OUTPUT_DIR/shard_*_entities.jsonl > $FINAL
echo "Total lines: $(wc -l < $FINAL)"
```

---

## Debugging Checklist

| Symptom | Diagnosis | Fix |
|---|---|---|
| `ModuleNotFoundError: nltk` | conda env missing nltk | `pip install nltk --break-system-packages` |
| Job stays in PD state | No GPUs available | Check: `sinfo -o "%n %G %t"` |
| Zero output lines in shard | Shard range calculation off | Print shard range in script, check against file count |
| CUDA OOM | Batch size too large for GPU | Reduce `--batch-size` from 32 → 16 |
| Job killed (timeout) | `--time` too short | Estimate: ~1min per 2,000 CVEs on 1 GPU |
| Empty log file | Wrong log path | Check `#SBATCH --output` path exists |

---

## File Transfer (local ↔ Paramananta)

```bash
# Copy output from Paramananta to local
scp -P 4422 suhani@paramananta.iitgn.ac.in:/scratch/suhani/cyner_project/output/cve_entities_all.jsonl ./

# Copy script to Paramananta
scp -P 4422 ./ner_worker.py suhani@paramananta.iitgn.ac.in:/scratch/suhani/cyner_project/code/

# Rsync (faster for many files)
rsync -avz -e "ssh -p 4422" ./output/ suhani@paramananta.iitgn.ac.in:/scratch/suhani/cyner_project/output/
```

---

## When NOT to Use Paramananta

- Running <10 PDFs — local Docling is fine
- Debugging code — use `srun` interactive session instead of `sbatch`
- Neo4j queries — run locally
- DSPy compilation with API calls — runs locally (network-dependent)
- Anything requiring internet access during job execution — Paramananta compute nodes may not have internet

## When TO Use Paramananta

- Full 50-shard CVE array job (323k records)
- Fine-tuning CyNER on custom annotated data
- Bulk Qdrant embedding generation (300k+ texts)
- Air-gapped operation (classified data must not leave HPC)
