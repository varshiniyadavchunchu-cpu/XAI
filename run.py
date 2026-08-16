import os
import sys
import subprocess
import venv
import shutil

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(PROJECT_ROOT, '.venv')

def get_python_executable():
    """
    Returns the path to the python executable within the virtual environment.
    """
    if sys.platform == 'win32':
        return os.path.join(VENV_DIR, 'Scripts', 'python.exe')
    return os.path.join(VENV_DIR, 'bin', 'python')

def get_pip_executable():
    """
    Returns the path to the pip executable within the virtual environment.
    """
    if sys.platform == 'win32':
        return os.path.join(VENV_DIR, 'Scripts', 'pip.exe')
    return os.path.join(VENV_DIR, 'bin', 'pip')

def is_venv_valid():
    """
    Checks if the virtual environment exists and is functional at the current project location.
    Virtual environments contain hardcoded absolute paths, so moving or renaming the project directory breaks them.
    """
    python_exe = get_python_executable()
    if not os.path.exists(python_exe):
        return False
    
    try:
        res = subprocess.run([python_exe, '-c', 'import sys; sys.exit(0)'], 
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        return res.returncode == 0
    except Exception:
        return False

def setup_venv():
    """
    Creates a virtual environment and installs dependencies if not already present or if invalid/moved.
    """
    if os.path.exists(VENV_DIR) and not is_venv_valid():
        print("Virtual environment is invalid or was created at a different folder path.")
        print(f"Removing old virtual environment at {VENV_DIR}...")
        try:
            shutil.rmtree(VENV_DIR)
        except Exception as e:
            print(f"Warning: Could not remove old .venv folder: {e}")

    if not os.path.exists(VENV_DIR):
        print(f"Creating fresh virtual environment in {VENV_DIR}...")
        venv.create(VENV_DIR, with_pip=True)
        print("Virtual environment created successfully.")
    else:
        print("Valid virtual environment found.")

    python_exe = get_python_executable()
    pip_exe = get_pip_executable()
    
    # Upgrade pip
    print("Upgrading pip...")
    subprocess.run([python_exe, '-m', 'pip', 'install', '--upgrade', 'pip'], check=True)

    # Install requirements
    req_file = os.path.join(PROJECT_ROOT, 'requirements.txt')
    if os.path.exists(req_file):
        print(f"Installing dependencies from {req_file}...")
        subprocess.run([pip_exe, 'install', '-r', req_file], check=True)
        print("Dependencies installed successfully.")
    else:
        print("Warning: requirements.txt not found. Skipping packages install.")

def train_model():
    """
    Executes model training using the virtual environment's python.
    """
    python_exe = get_python_executable()
    print("Pre-training Random Forest classifier and building XAI baseline context...")
    
    # We execute an inline script in the virtual environment python context
    script = (
        "import sys, os; "
        "sys.path.insert(0, os.path.abspath('.')); "
        "from backend.model_handler import train_ids_model; "
        "train_ids_model(num_samples=10000)"
    )
    
    subprocess.run([python_exe, '-c', script], check=True)
    print("Initial model training completed.")

def run_server():
    """
    Starts the FastAPI server with live reload.
    """
    python_exe = get_python_executable()
    print("\n" + "="*60)
    print("Starting Explainable AI IDS Server...")
    print("Dashboard will be available at: http://127.0.0.1:8000")
    print("="*60 + "\n")
    
    # We call uvicorn module inside the venv python
    cmd = [
        python_exe, '-m', 'uvicorn', 
        'backend.main:app', 
        '--host', '127.0.0.1', 
        '--port', '8000', 
        '--reload'
    ]
    
    # Run uvicorn server (blocks process until terminated)
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\nStopping IDS Server. Goodbye!")

if __name__ == '__main__':
    # Ensure current working directory is project root
    os.chdir(PROJECT_ROOT)
    
    try:
        setup_venv()
        
        # Check if model has already been trained
        model_path = os.path.join(PROJECT_ROOT, 'data', 'model.joblib')
        if not os.path.exists(model_path):
            train_model()
        else:
            print("Trained model found. Skipping initial training step.")
            
        run_server()
        
    except Exception as e:
        print(f"\nError occurred during execution: {e}", file=sys.stderr)
        sys.exit(1)

