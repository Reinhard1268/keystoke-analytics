🧠 Keystroke Analytics
🔍 Overview
Keystroke Analytics is a lightweight, Python-based monitoring tool that logs keyboard activity and performs behavioral analytics on the data. It helps cybersecurity professionals and enthusiasts understand user input patterns—great for ethical hacking, behavioral research, or training simulations.

⚠️ For Educational Purposes Only: This tool must only be used in environments you own or have permission to monitor. Misuse may violate laws.

🚀 Features
 • ⌨️ Real-time keystroke logging
 • 📈 Analytics on typing patterns (speed, frequency, etc.)
 • 🧪 Easy to test and demo with optional visualization output
 • 🔒 Secure storage for logs
 • 🛠️ Portable .exe build using PyInstaller
 • 🧠 Easy-to-read keystroke analysis report

📁 Project Structure
keystroke-analytics/
├── build/                      # Build files
├── dist/                       # Executable binary (.exe) goes here
├── keylogs/                    # Log files directory
├── keylogger.py               # Main script
├── keystroke_analytics.bin    # (Optional) PyInstaller binary
├── keystroke_analytics.bin.decrypted.txt  # Decrypted keystroke logs
├── keylog.txt                 # Plain text logs
├── keylogger.spec             # PyInstaller spec file
├── requirements.txt           # Dependencies
├── README.md                  # This file
└── banner.png                 # Custom banner for this project

🧪 Usage

▶️ Run via Python:
python keylogger.py

🧊 Build .exe with PyInstaller:
pyinstaller --onefile --windowed keylogger.py
Note: The executable will be available inside the /dist/directory.

📊 Output Samples
 • keylog.txt
Captures raw keystrokes in sequence.
 • keystroke_analytics.bin.decrypted.txt
Shows enriched insights like character frequency, delay between keys, etc.

📦 Requirements

Install dependencies:
pip install -r requirements.txt

OR Manually:
pip install pynput 

📌 TO DO (Next Versions)
 • GUI to visualize analytics in real-time
 • Export analytics report to PDF/CSV
 • Add anomaly detection
 • Auto-delete sensitive logs after analysis

🧠 Author

[Reinhard Amoah]
Cybersecurity Enthusiast |EC COUNCIL Trained CCT | Ethical Hacking Learner | Python Developer
📫 Contact: [bonnkeygrantreinhard@gmail.com] 
🌐 GitHub: [github.com/Reinhard1268]

🛡️ Disclaimer

This tool is intended for ethical use only. Use responsibly and within the legal boundaries of your jurisdiction.
