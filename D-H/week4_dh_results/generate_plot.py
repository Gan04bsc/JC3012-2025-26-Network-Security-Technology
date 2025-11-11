import matplotlib.pyplot as plt
import numpy as np

# --- Data Preparation ---
# Experiment 1 (Baseline): Attack success rate 100%
# Experiment 2 (Defended): Attack success rate 0%
labels = ['Experiment 1: Basic D-H (Baseline)', 'Experiment 2: D-H + PSK/HMAC (Defended)']
success_rates = [100, 0]

# --- Plotting Setup ---
fig, ax = plt.subplots(figsize=(10, 6))

colors = ['#D9534F', '#5CB85C'] # Red for attack success, Green for defense success
bars = ax.bar(labels, success_rates, color=colors, width=0.5)

# --- Customize Chart ---
ax.set_ylabel('MITM Attack Success Rate (%)', fontsize=12)
ax.set_title('Diffie-Hellman (D-H) Man-in-the-Middle (MITM) Attack and Defense Comparison', fontsize=16, pad=20)
ax.set_ylim(0, 110) # Leave some space at the top
ax.grid(axis='y', linestyle='--', alpha=0.7)

# Display percentage on top of bars
for bar in bars:
    height = bar.get_height()
    ax.annotate(f'{height}%',
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3),  # 3 points vertical offset
                textcoords="offset points",
                ha='center', va='bottom', fontsize=12)

# Save the chart
output_filename = 'dh_comparison_chart_english.png' # Changed filename to indicate English version
plt.savefig(output_filename)

print(f"English comparison chart saved as: {output_filename}")

# Optional: Show the chart
# plt.show()
