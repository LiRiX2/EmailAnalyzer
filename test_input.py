import sys

print("--- Input Test Started ---")
print("This script will ask for your input.")
try:
    # Versucht, eine Eingabe vom Benutzer zu erhalten
    user_response = input("Please type anything and press Enter: ")
    print(f"You entered: '{user_response}'")
    print("Input test successful.")
except Exception as e:
    print(f"An error occurred during input: {e}")
    print("Input test FAILED.")

print("--- Input Test Finished ---")

# Wenn das Skript direkt über eine IDE oder ein normales Terminal ausgeführt wird,
# sollte sys.stdin.isatty() True sein. Wenn es in bestimmten Skript-Runnern läuft,
# kann es False sein, was input() blockieren könnte.
if not sys.stdin.isatty():
    print("Warning: sys.stdin is not a TTY. Input may not work interactively.")