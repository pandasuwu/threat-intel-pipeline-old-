rm -f ~/Workspace/slurm/00_setup_on_login_node.sh

python3 << 'PYEOF'
import os

script = """\
#!/usr/bin/env bash
# requires: nltk punkt corpus (downloaded below)
set -euo pipefail

HOME_DIR="/home/${USER}"
SCRATCH="/scratch/${USER}"
PROJECT_DIR="${SCRATCH}/cyner_project"
WORKSPACE="${HOME_DIR}/Workspace"
CONDA_ENV_NAME="cyner_env_310"
PYTHON_VERSION="3.10"

echo "===================================================="
echo " PARAM Ananta -- CyNER Setup | User: ${USER}"
echo " Scratch: ${SCRATCH} | Project: ${PROJECT_DIR}"
echo "===================================================="

mkdir -p "${PROJECT_DIR}"/{data,output/cve_shards,logs,models,code}
echo "[1/5] Directories created"

if [ ! -d "${HOME_DIR}/miniconda3" ]; then
    echo "[1.5] Installing Miniconda..."
    wget -q https://repo.anaconda.com/miniconda/Miniconda3-py310_23.10.0-1-Linux-x86_64.sh -O /tmp/miniconda.sh
    bash /tmp/miniconda.sh -b -p "${HOME_DIR}/miniconda3"
    rm /tmp/miniconda.sh
fi
source "${HOME_DIR}/miniconda3/etc/profile.d/conda.sh"

if conda env list | grep -q "^${CONDA_ENV_NAME}[[:space:]]"; then
    echo "[2/5] Conda env exists -- skipping creation"
else
    echo "[2/5] Creating conda env (Python ${PYTHON_VERSION})..."
    conda create -y -n "${CONDA_ENV_NAME}" python="${PYTHON_VERSION}"
fi
conda activate "${CONDA_ENV_NAME}"

if python -c "import transformers, spacy, torch" 2>/dev/null; then
    echo "[2/5] Core packages already installed -- skipping"
else
    echo "[2/5] Installing packages..."
    pip install --quiet --upgrade pip wheel setuptools
    conda install -y --quiet -c conda-forge "numpy<2.0.0" scipy scikit-learn pandas pyarrow "matplotlib>=3.7"
    pip install --quiet --only-binary :all: torch==2.2.2 --index-url https://download.pytorch.org/whl/cu118
    pip install --quiet --only-binary :all: "markupsafe>=2.1.1,<3.0" "jinja2>=3.1,<4.0"
    pip install --quiet --only-binary :all: "spacy==3.7.4" "thinc==8.2.3"
    pip install --quiet --only-binary :all: "transformers==4.40.2" "tokenizers==0.19.1" "seqeval==1.2.2" "huggingface-hub==0.23.0" "accelerate==0.30.0" "datasets==2.19.1"
    python -m spacy download en_core_web_sm
    echo "[2/5] Packages installed"
fi

CYNER_DIR="${HOME_DIR}/Workspace/cyner_src"
if [ -d "${CYNER_DIR}" ]; then
    echo "[2b] CyNER already cloned -- skipping"
else
    echo "[2b] Cloning CyNER..."
    git clone --quiet https://github.com/aiforsec/CyNER.git "${CYNER_DIR}"
    printf 'transformers>=4.40.0\\nseqeval>=1.2.2\\n' > "${CYNER_DIR}/requirements.txt"
    if [ -f "${CYNER_DIR}/setup.py" ]; then
        sed -i -e 's/jinja2==[^",]*//' -e 's/matplotlib==[^",]*//' -e 's/markupsafe==[^",]*//' -e 's/werkzeug==[^",]*//' "${CYNER_DIR}/setup.py"
    fi
    pip install --quiet --no-deps -e "${CYNER_DIR}"
    echo "[2b] CyNER installed"
fi
export PYTHONPATH="${CYNER_DIR}:${PYTHONPATH:-}"

export HF_HOME="${PROJECT_DIR}/models"
export HF_HUB_CACHE="${PROJECT_DIR}/models"
mkdir -p "${PROJECT_DIR}/models"

if [ -d "${PROJECT_DIR}/models/models--xlm-roberta-large" ]; then
    echo "[3/5] Model already cached -- skipping"
else
    echo "[3/5] Downloading xlm-roberta-large (~1.1 GB)..."
    python3 -c "
from transformers import AutoTokenizer, AutoModelForTokenClassification
print('Downloading tokenizer...')
AutoTokenizer.from_pretrained('xlm-roberta-large')
print('Downloading weights...')
AutoModelForTokenClassification.from_pretrained('xlm-roberta-large')
print('Done')
"
fi
echo "[3/5] Model ready"

echo "[4/5] Copying data and scripts..."

while IFS= read -r -d '' f; do
    cp "$f" "${PROJECT_DIR}/data/"
done < <(find "${WORKSPACE}/parse/" -maxdepth 1 -name "*.json" ! -name "*_ner.json" -print0 2>/dev/null)
echo "  Chunk JSONs copied"

if [ -f "${WORKSPACE}/cve_normalized.jsonl" ]; then
    cp "${WORKSPACE}/cve_normalized.jsonl" "${PROJECT_DIR}/data/"
    echo "  cve_normalized.jsonl copied"
else
    echo "  WARNING: cve_normalized.jsonl not found -- skipping"
fi

if [ -f "${WORKSPACE}/parse/ner_worker.py" ]; then
    cp "${WORKSPACE}/parse/ner_worker.py" "${PROJECT_DIR}/code/"
    echo "  ner_worker.py copied"
else
    echo "  WARNING: ner_worker.py not found -- skipping"
fi
echo "[4/5] Data copied"

CONDA_BASE_PATH="\$(conda info --base)"
echo "SCRATCH=\${SCRATCH}"                    >  "\${PROJECT_DIR}/env.conf"
echo "PROJECT_DIR=\${PROJECT_DIR}"           >> "\${PROJECT_DIR}/env.conf"
echo "CONDA_ENV_NAME=\${CONDA_ENV_NAME}"     >> "\${PROJECT_DIR}/env.conf"
echo "CONDA_BASE=\${CONDA_BASE_PATH}"        >> "\${PROJECT_DIR}/env.conf"
echo "CYNER_DIR=\${CYNER_DIR}"               >> "\${PROJECT_DIR}/env.conf"
echo "HF_HOME=\${PROJECT_DIR}/models"        >> "\${PROJECT_DIR}/env.conf"
echo "HF_HUB_CACHE=\${PROJECT_DIR}/models"  >> "\${PROJECT_DIR}/env.conf"
echo "PYTHONPATH=\${CYNER_DIR}"              >> "\${PROJECT_DIR}/env.conf"
echo "[5/5] env.conf written"

echo ""
echo "===================================================="
echo " SETUP COMPLETE"
echo " Data files : \$(ls \${PROJECT_DIR}/data/ | wc -l)"
echo " CyNER src  : \${CYNER_DIR}"
echo " Models dir : \${PROJECT_DIR}/models"
echo " Next step  : sbatch ~/Workspace/slurm/submit_ner_pdfs.sh"
echo "===================================================="
"""

path = os.path.expanduser("~/Workspace/slurm/00_setup_on_login_node.sh")
with open(path, "w", encoding="utf-8") as f:
    f.write(script)

# Verify it wrote correctly
with open(path, "r") as f:
    lines = f.readlines()
print("Written: " + str(len(lines)) + " lines to " + path)
print("First line: " + lines[0].strip())
print("Last line:  " + lines[-1].strip())
PYEOF

chmod +x ~/Workspace/slurm/00_setup_on_login_node.sh

# Confirm the file looks right before running
echo "--- First 5 lines ---"
head -5 ~/Workspace/slurm/00_setup_on_login_node.sh
echo "--- Last 5 lines ---"
tail -5 ~/Workspace/slurm/00_setup_on_login_node.sh