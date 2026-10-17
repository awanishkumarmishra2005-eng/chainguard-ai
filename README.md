ChainGuard AI — Graph-Based Cybersecurity Investigation

ChainGuard AI is a cybersecurity investigation prototype built with Flask and FalkorDB. It provides an interactive dashboard, graph-based investigation paths, event logs, connected-entity details, and AI explanations using Ollama.

Features

- Interactive dashboard: Explore investigation data and logs.
- Graph exploration: Click graph nodes to inspect their associated details.
- Investigation paths: Explore relationships between users, events, IP addresses, and devices.
- AI chatbot: Ask questions and receive explanations.
- Local AI: Use Ollama with the "qwen2.5:1.5b" model.
- Graph database: Use FalkorDB to store and query investigation relationships.

Requirements

Install the following software:

- Python
- Docker Desktop
- Ollama
- Git (if cloning the repository)

Windows PowerShell installation

1. Get the project

Clone the repository:

git clone https://github.com/awanishkumarmishra2005-eng/chainguard-ai.git
cd chainguard-ai

If the application files are inside a subfolder, navigate to the directory containing "app.py" and "requirements.txt".

Alternatively, extract the project ZIP and open its "chainguard_fixed" folder in VS Code.

2. Start FalkorDB

Open Docker Desktop.

If the "chainguard-db" container already exists:

docker start chainguard-db

If it does not exist, create it:

docker run --name chainguard-db -p 6379:6379 -p 3000:3000 -d falkordb/falkordb:latest

Verify that the container is running:

docker ps
docker exec -it chainguard-db redis-cli PING

Expected response:

PONG

3. Install and prepare Ollama

Install Ollama, then download the model:

ollama pull qwen2.5:1.5b

Verify that the model is available:

ollama list

Ollama must be running for locally generated AI explanations.

4. Install Python dependencies

From the directory containing "requirements.txt", run:

python -m pip install -r requirements.txt

5. Start ChainGuard AI

Stop any older Flask server with "Ctrl+C" before starting the application.

For local execution with FalkorDB and Ollama, run:

$env:DEMO_MODE = "false"
python app.py

Keep the terminal open.

Open the application in your browser:

http://127.0.0.1:5000

6. Load and explore investigation data

Use Load Demo Data if the graph needs to be populated.

Then explore:

1. The dashboard and previous investigation logs.
2. Investigate Events.
3. Trace Threat Paths.
4. Click graph nodes to inspect their details.
5. Use the chatbot to ask investigation-related questions.

The data-loading behavior depends on the application's existing implementation. If the graph is empty, check the Flask terminal and the project's data initialization endpoint.

API verification

With Flask running, open a second PowerShell terminal.

Check application health:

Invoke-RestMethod http://127.0.0.1:5000/api/health

Check graph data:

Invoke-RestMethod http://127.0.0.1:5000/api/graph

Check investigation paths:

Invoke-RestMethod http://127.0.0.1:5000/api/investigate-paths

Test the AI explanation endpoint:

$body = @{
    question = "Explain the investigation evidence and distinguish observed facts from possible risks."
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "http://127.0.0.1:5000/api/ai-explain" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body

Hosted demo and local execution

The hosted deployment runs in demo mode and does not connect to the developer's local FalkorDB or Ollama services.

The local setup can use FalkorDB and Ollama when they are running and configured correctly. AI-generated wording may vary between runs.

Troubleshooting

FalkorDB connection error: Start Docker Desktop and verify that the database container is running.

Ollama connection error: Start Ollama and check that "qwen2.5:1.5b" is installed.

No investigation paths: Load the demo data and check the Flask terminal for errors.

Port 5000 is occupied: Stop the older Flask process before restarting the application.

Evaluation notes

- This project is a cybersecurity investigation prototype.
- Demo identities, events, and relationships are fictional.
- A graph relationship is an investigation lead, not proof of malicious activity.
- AI explanations are informational and should be verified against the available evidence.
- Do not use this prototype as the sole basis for real-world security decisions.