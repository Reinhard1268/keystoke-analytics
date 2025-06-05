import os
import sys
import time
import argparse
import threading
import smtplib
import json
from datetime import datetime, timedelta
from pynput import keyboard
from cryptography.fernet import Fernet
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
try:
    import tkinter as tk
    from tkinter import messagebox
    GUI_ENABLED = True
except ImportError:
    GUI_ENABLED = False
try:
    from pygetwindow import getActiveWindow
    WINDOW_TRACKING = True
except ImportError:
    WINDOW_TRACKING = False

# Configuration
LOG_FILE = "keystroke_analytics.bin"
MAX_KEYS = 500
MAX_LOG_SIZE_MB = 1
MAX_LOG_AGE_DAYS = 7
ENCRYPTION_KEY_FILE = "analytics.key"
CLEANUP_INTERVAL = 3600  # Cleanup every hour
EMAIL_INTERVAL = 86400   # Email report daily

# Global state
USER_CONSENT = False
LOG_ENABLED = False
keystrokes = []
listener = None
silent_mode = False
cleanup_thread = None
running = True
testing_mode = False
last_key_time = None
current_window = "Unknown"

# CLI Argument Parser
def parse_args():
    parser = argparse.ArgumentParser(description='Ethical Keystroke Analytics Tool')
    parser.add_argument('--silent', action='store_true', help='Skip consent prompts and start logging immediately')
    parser.add_argument('--cleanup', action='store_true', help='Run log cleanup and exit')
    parser.add_argument('--decrypt', metavar='LOG_FILE', help='Decrypt specified log file')
    parser.add_argument('--key', metavar='KEY_FILE', default=ENCRYPTION_KEY_FILE, 
                        help=f'Encryption key file (default: {ENCRYPTION_KEY_FILE})')
    parser.add_argument('--test', action='store_true', help='Enable testing mode (print keys to console)')
    return parser.parse_args()

# Encryption Functions
def generate_encryption_key():
    key = Fernet.generate_key()
    with open(ENCRYPTION_KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key

def load_encryption_key():
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, "rb") as key_file:
            return key_file.read()
    return generate_encryption_key()

def encrypt_data(data, fernet):
    return fernet.encrypt(json.dumps(data).encode())

def decrypt_data(encrypted_data, fernet):
    return json.loads(fernet.decrypt(encrypted_data).decode())

# Log Management
def rotate_log_file():
    if os.path.exists(LOG_FILE):
        size_mb = os.path.getsize(LOG_FILE) / (1024 * 1024)
        if size_mb > MAX_LOG_SIZE_MB:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            new_file = f"keystroke_analytics_{timestamp}.bin"
            os.rename(LOG_FILE, new_file)
            return new_file
    return None

def cleanup_old_logs():
    now = datetime.now()
    cutoff = now - timedelta(days=MAX_LOG_AGE_DAYS)
    
    for filename in os.listdir('.'):
        if filename.startswith("keystroke_analytics_") and filename.endswith(".bin"):
            try:
                file_time = datetime.fromtimestamp(os.path.getctime(filename))
                if file_time < cutoff:
                    os.remove(filename)
                    print(f"[+] Removed old log: {filename}")
            except:
                pass

def periodic_cleanup():
    while running:
        cleanup_old_logs()
        time.sleep(CLEANUP_INTERVAL)

# Email Reporting
def load_email_config():
    config_path = "email_config.json"
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                return json.load(f)
        except:
            return None
    return None

def send_email_report():
    config = load_email_config()
    if not config:
        print("[!] Email not configured. Create email_config.json")
        return
    
    fernet = Fernet(load_encryption_key())
    
    # Prepare analytics summary
    summary = generate_analytics_summary()
    
    # Create email
    msg = MIMEMultipart()
    msg['From'] = config['sender_email']
    msg['To'] = config['receiver_email']
    msg['Subject'] = f"Keystroke Analytics Report - {datetime.now().strftime('%Y-%m-%d')}"
    
    # Attach summary as text
    msg.attach(MIMEText(summary, 'plain'))
    
    # Attach log files
    for filename in os.listdir('.'):
        if filename.startswith("keystroke_analytics_") and filename.endswith(".bin"):
            try:
                with open(filename, "rb") as f:
                    part = MIMEApplication(f.read(), Name=filename)
                part['Content-Disposition'] = f'attachment; filename="{filename}"'
                msg.attach(part)
            except Exception as e:
                print(f"[!] Failed to attach {filename}: {str(e)}")
    
    # Send email
    try:
        with smtplib.SMTP_SSL(config['smtp_server'], config['smtp_port']) as server:
            server.login(config['sender_email'], config['sender_password'])
            server.send_message(msg)
        print("[+] Email report sent successfully")
    except Exception as e:
        print(f"[!] Email failed: {str(e)}")

def email_scheduler():
    while running:
        now = datetime.now()
        # Send at 2 AM daily
        if now.hour == 2 and now.minute == 0:
            send_email_report()
        time.sleep(60)  # Check every minute

# Analytics Functions
def get_active_window():
    global current_window
    if not WINDOW_TRACKING:
        return "Tracking Disabled"
    
    try:
        window = getActiveWindow()
        return window.title if window else "Unknown"
    except:
        return "Unknown"

def generate_analytics_summary():
    if not keystrokes:
        return "No keystroke data available"
    
    total_keys = len(keystrokes)
    window_stats = {}
    key_intervals = []
    
    # Calculate timing and window stats
    prev_time = None
    for entry in keystrokes:
        # Window statistics
        window = entry['window']
        window_stats[window] = window_stats.get(window, 0) + 1
        
        # Timing statistics
        if prev_time:
            interval = (entry['timestamp'] - prev_time).total_seconds()
            key_intervals.append(interval)
        prev_time = entry['timestamp']
    
    # Calculate analytics
    total_time = (keystrokes[-1]['timestamp'] - keystrokes[0]['timestamp']).total_seconds()
    wpm = (total_keys / 5) / (total_time / 60) if total_time > 0 else 0
    avg_interval = sum(key_intervals) / len(key_intervals) if key_intervals else 0
    
    # Generate report
    report = f"Keystroke Analytics Summary - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    report += "=" * 60 + "\n"
    report += f"Total Keys: {total_keys}\n"
    report += f"Session Duration: {total_time:.2f} seconds\n"
    report += f"Average Typing Speed: {wpm:.2f} WPM\n"
    report += f"Average Key Interval: {avg_interval:.3f} seconds\n\n"
    report += "Application Usage:\n"
    
    for window, count in window_stats.items():
        percentage = (count / total_keys) * 100
        report += f"  {window[:50]}: {count} keys ({percentage:.1f}%)\n"
    
    report += "\n" + "=" * 60
    return report

# Core Functions
def save_log():
    if not keystrokes:
        return
    
    fernet = Fernet(load_encryption_key())
    
    # Add analytics summary to the log
    log_data = {
        'meta': {
            'start_time': keystrokes[0]['timestamp'].isoformat(),
            'end_time': datetime.now().isoformat(),
            'total_keys': len(keystrokes)
        },
        'keystrokes': keystrokes,
        'summary': generate_analytics_summary()
    }
    
    encrypted_data = encrypt_data(log_data, fernet)
    
    rotated_file = rotate_log_file()
    with open(LOG_FILE, "ab") as f:
        f.write(encrypted_data)
    
    keystrokes.clear()
    print("[+] Log saved securely")
    
    if rotated_file and testing_mode:
        print(f"[TEST] Log rotated: {rotated_file}")

def show_consent():
    global USER_CONSENT
    
    if silent_mode:
        USER_CONSENT = True
        return
    
    print("\n" + "="*60)
    print("ETHICAL KEYSTROKE ANALYTICS TOOL".center(60))
    print("="*60)
    print("This tool collects anonymized typing metrics for:")
    print("- Productivity analysis\n- UX research\n- Accessibility improvements")
    print("\nNOTICE:")
    print("- Data is encrypted and stored locally")
    print("- Logs auto-delete after 7 days")
    print("- You control when logging starts/stops")
    print("="*60)
    
    consent = input("\nDo you consent to proceed? (yes/no): ").lower()
    if consent != 'yes':
        print("Consent denied. Exiting...")
        sys.exit(0)
    
    USER_CONSENT = True
    print("\nConsent confirmed. Press F12 to START/STOP logging")

def toggle_logging(state=None):
    global LOG_ENABLED, last_key_time
    
    if state is None:
        LOG_ENABLED = not LOG_ENABLED
    else:
        LOG_ENABLED = state
        
    status = "ENABLED" if LOG_ENABLED else "DISABLED"
    print(f"\n[!] Logging {status}")
    
    if LOG_ENABLED:
        last_key_time = None
        update_current_window()
    
    if not LOG_ENABLED:
        save_log()

def update_current_window():
    global current_window
    current_window = get_active_window()

# Key Listener
def on_press(key):
    global last_key_time, current_window
    
    if key == keyboard.Key.f12:
        toggle_logging()
        return
    if key == keyboard.Key.esc:
        shutdown()
        return False
    
    if not (USER_CONSENT and LOG_ENABLED):
        return
    
    try:
        # Capture active window periodically
        if last_key_time and (time.time() - last_key_time > 5):
            update_current_window()
        
        # Capture key and metadata
        key_data = {
            'timestamp': datetime.now(),
            'window': current_window
        }
        
        if hasattr(key, 'char') and key.char:
            key_data['key'] = key.char
            if testing_mode:
                print(f"[TEST] Key: {key.char} | Window: {current_window}")
        else:
            key_name = str(key).replace("Key.", "").capitalize()
            key_data['key'] = f"[{key_name}]"
            if testing_mode:
                print(f"[TEST] Special: {key_name} | Window: {current_window}")
        
        keystrokes.append(key_data)
        last_key_time = time.time()
        
        # Capture timing between keys
        if len(keystrokes) > 1:
            prev = keystrokes[-2]['timestamp']
            current = keystrokes[-1]['timestamp']
            interval = (current - prev).total_seconds()
            if testing_mode:
                print(f"[TEST] Interval: {interval:.3f}s")
        
    except Exception as e:
        print(f"Error processing key: {e}")
    
    # Automatic save threshold
    if len(keystrokes) >= MAX_KEYS:
        save_log()

def start_listener():
    global listener
    listener = keyboard.Listener(on_press=on_press)
    listener.start()

# GUI Functions
def create_tray_icon():
    if not GUI_ENABLED:
        print("GUI disabled: tkinter not available")
        return
    
    root = tk.Tk()
    root.title("Keystroke Analytics")
    root.geometry("350x200")
    root.resizable(False, False)
    
    def on_close():
        global running
        running = False
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_close)
    
    status_var = tk.StringVar(value="Logging: OFF")
    stats_var = tk.StringVar(value="Keys: 0 | Windows: 0")
    
    def update_status():
        status_var.set(f"Logging: {'ON' if LOG_ENABLED else 'OFF'}")
        window_count = len(set(entry['window'] for entry in keystrokes))
        stats_var.set(f"Keys: {len(keystrokes)} | Windows: {window_count}")
    
    def toggle_gui():
        toggle_logging()
        update_status()
    
    def show_summary():
        summary = generate_analytics_summary()
        messagebox.showinfo("Analytics Summary", summary)
    
    tk.Label(root, text="Ethical Keystroke Analytics", font=("Arial", 14)).pack(pady=10)
    status_label = tk.Label(root, textvariable=status_var, font=("Arial", 12))
    status_label.pack(pady=5)
    
    stats_label = tk.Label(root, textvariable=stats_var, font=("Arial", 10))
    stats_label.pack(pady=2)
    
    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=10)
    
    tk.Button(btn_frame, text="Toggle Logging", command=toggle_gui, width=15).pack(side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text="View Summary", command=show_summary, width=15).pack(side=tk.LEFT, padx=5)
    
    tk.Button(root, text="Save & Exit", command=on_close, width=15).pack(pady=5)
    
    # Periodic UI update
    def ui_update():
        if running:
            update_status()
            root.after(5000, ui_update)  # Update every 5 seconds
    
    update_status()
    ui_update()
    root.mainloop()

# Decryption Tool
def decrypt_log(log_file, key_file):
    if not os.path.exists(log_file):
        print(f"Error: Log file not found - {log_file}")
        return
    
    if not os.path.exists(key_file):
        print(f"Error: Key file not found - {key_file}")
        return
    
    try:
        with open(key_file, "rb") as f:
            key = f.read()
        
        with open(log_file, "rb") as f:
            encrypted_data = f.read()
        
        fernet = Fernet(key)
        decrypted_data = decrypt_data(encrypted_data, fernet)
        
        output_file = f"{log_file}.decrypted.json"
        with open(output_file, "w") as f:
            json.dump(decrypted_data, f, indent=2)
        
        # Also output summary as text
        summary_file = f"{log_file}_summary.txt"
        with open(summary_file, "w") as f:
            f.write(decrypted_data.get('summary', 'No summary available'))
        
        print(f"[+] Successfully decrypted log to {output_file}")
        print(f"[+] Summary saved to {summary_file}")
        print(f"[!] Remember to delete decrypted files after use")
    
    except Exception as e:
        print(f"Decryption failed: {str(e)}")

# System Control
def shutdown():
    global running
    running = False
    
    if LOG_ENABLED:
        save_log()
    
    if listener:
        listener.stop()
    
    print("\n[+] Analytics tool stopped")
    print(f"[+] Decryption key: {ENCRYPTION_KEY_FILE}")

def main():
    global silent_mode, running, cleanup_thread, testing_mode
    
    args = parse_args()
    silent_mode = args.silent
    testing_mode = args.test
    
    if args.decrypt:
        decrypt_log(args.decrypt, args.key)
        return
    
    if args.cleanup:
        cleanup_old_logs()
        return
    
    # Start periodic cleanup thread
    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
    cleanup_thread.start()
    
    # Start email scheduler
    email_thread = threading.Thread(target=email_scheduler, daemon=True)
    email_thread.start()
    
    show_consent()
    
    if silent_mode:
        toggle_logging(True)
        print("\n[+] Silent mode activated - logging started")
    else:
        print("\n[!] Press F12 to begin analytics")
    
    print("[!] Press ESC to exit\n")
    
    # Start key listener
    start_listener()
    
    # Start GUI if available
    if GUI_ENABLED and not silent_mode:
        gui_thread = threading.Thread(target=create_tray_icon, daemon=True)
        gui_thread.start()
    
    # Keep main thread alive
    try:
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        shutdown()

if __name__ == "__main__":
    main()
