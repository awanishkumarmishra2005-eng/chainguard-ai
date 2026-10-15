# ChainGuard AI — fixed copy-and-run project

This project includes the Flask backend and the updated dashboard HTML together. The backend includes both `/api/investigate` and `/api/investigate-paths` so the frontend does not depend on a missing route.

## Windows PowerShell setup

1. Extract this ZIP.
2. Open the extracted `chainguard_fixed` folder in VS Code.
3. Start FalkorDB. If your container already exists:

   ```powershell
   docker start chainguard-db
   ```

   If Docker says the container does not exist, create it:

   ```powershell
   docker run --name chainguard-db -p 6379:6379 -p 3000:3000 -d falkordb/falkordb:latest
   ```

4. Install the Python packages:

   ```powershell
   python -m pip install -r requirements.txt
   ```

5. Start the app:

   ```powershell
   python app.py
   ```

6. Open `http://127.0.0.1:5000`, click **Load Demo Data**, then **Investigate Events** or **Trace Threat Paths**.

If you already have an older Flask server running, stop it with `Ctrl+C` before starting this version. Demo data is fictional; a HIGH label is a demo rule, not proof of an attack.
