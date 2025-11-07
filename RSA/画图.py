import matplotlib.pyplot as plt
import numpy as np
import json
from matplotlib import rcParams

# Set default font to support Unicode
rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial']
rcParams['axes.unicode_minus'] = False

# 实验数据（来自 experiment_1_summary_20251106_095840.txt）
baseline_data = {
    'bits': [64, 80, 96, 112, 128, 256, 512],
    'asr': [100.0, 100.0, 100.0, 80.0, 0.0, 0.0, 0.0],
    'avg_time': [0.027, 0.458, 22.519, 617.496, 2502.970, 4656.116, 9539.208],
    'success': [10, 10, 8, 4, 0, 0, 0],
    'total': [10, 10, 8, 5, 3, 5, 3]
}

# weak_imbalanced 数据
weak_imbalanced_256 = {
    'bits': 256,
    'asr': 100.0,
    'avg_time': 4.845,
    'success': 10,
    'total': 10
}

def create_visualizations():
    """Create comprehensive visualization of experimental results"""
    
    # Create a large figure with multiple subplots
    fig = plt.figure(figsize=(16, 10))
    
    # ========== Subplot 1: ASR vs Bit Length ==========
    ax1 = plt.subplot(2, 3, 1)
    colors = ['#2ecc71' if asr == 100 else '#e74c3c' if asr == 0 else '#f39c12' 
              for asr in baseline_data['asr']]
    bars1 = ax1.bar(range(len(baseline_data['bits'])), baseline_data['asr'], 
                     color=colors, alpha=0.7, edgecolor='black', linewidth=1.5)
    ax1.set_xlabel('Modulus Bit Length', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Attack Success Rate (ASR %)', fontsize=12, fontweight='bold')
    ax1.set_title('RSA Baseline: ASR vs Bit Length', fontsize=14, fontweight='bold')
    ax1.set_xticks(range(len(baseline_data['bits'])))
    ax1.set_xticklabels(baseline_data['bits'])
    ax1.set_ylim(0, 110)
    ax1.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Add value labels
    for i, (bar, asr, success, total) in enumerate(zip(bars1, baseline_data['asr'], 
                                                         baseline_data['success'], 
                                                         baseline_data['total'])):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 2,
                f'{asr:.0f}%\n({success}/{total})',
                ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    # ========== Subplot 2: Attack Time vs Bit Length (Log Scale) ==========
    ax2 = plt.subplot(2, 3, 2)
    ax2.plot(baseline_data['bits'], baseline_data['avg_time'], 
             marker='o', linewidth=2.5, markersize=8, color='#3498db', 
             label='Baseline (Balanced Primes)')
    ax2.set_xlabel('Modulus Bit Length', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Average Attack Time (seconds)', fontsize=12, fontweight='bold')
    ax2.set_title('Exponential Growth of Attack Time', fontsize=14, fontweight='bold')
    ax2.set_yscale('log')
    ax2.grid(True, alpha=0.3, which='both', linestyle='--')
    ax2.legend(fontsize=10)
    
    # Add value labels
    for x, y in zip(baseline_data['bits'], baseline_data['avg_time']):
        if y < 1:
            label = f'{y:.3f}s'
        elif y < 100:
            label = f'{y:.2f}s'
        else:
            label = f'{y:.0f}s'
        ax2.annotate(label, (x, y), textcoords="offset points", 
                    xytext=(0,8), ha='center', fontsize=8)
    
    # ========== Subplot 3: 256-bit Baseline vs Weak_Imbalanced Comparison ==========
    ax3 = plt.subplot(2, 3, 3)
    categories = ['256-bit\nBaseline\n(Balanced)', '256-bit\nWeak_Imbalanced\n(Imbalanced p≈40-bit)']
    asr_values = [0.0, 100.0]
    time_values = [4656.116, 4.845]
    
    x_pos = np.arange(len(categories))
    bars3 = ax3.bar(x_pos, asr_values, color=['#e74c3c', '#2ecc71'], 
                     alpha=0.7, edgecolor='black', linewidth=1.5)
    ax3.set_ylabel('Attack Success Rate (ASR %)', fontsize=12, fontweight='bold')
    ax3.set_title('256-bit: Balanced vs Imbalanced Primes', fontsize=14, fontweight='bold')
    ax3.set_xticks(x_pos)
    ax3.set_xticklabels(categories, fontsize=10)
    ax3.set_ylim(0, 110)
    ax3.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Add labels
    for i, (bar, asr, time) in enumerate(zip(bars3, asr_values, time_values)):
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height + 2,
                f'ASR: {asr:.0f}%\nTime: {time:.2f}s',
                ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    # ========== Subplot 4: ASR and Time Dual Y-axis Comparison ==========
    ax4 = plt.subplot(2, 3, 4)
    ax4_twin = ax4.twinx()
    
    # Success rate curve
    line1 = ax4.plot(baseline_data['bits'], baseline_data['asr'], 
                     marker='s', linewidth=2.5, markersize=8, color='#e74c3c', 
                     label='ASR (%)', zorder=3)
    ax4.set_xlabel('Modulus Bit Length', fontsize=12, fontweight='bold')
    ax4.set_ylabel('Attack Success Rate (%)', fontsize=12, fontweight='bold', color='#e74c3c')
    ax4.tick_params(axis='y', labelcolor='#e74c3c')
    ax4.set_ylim(-5, 110)
    
    # Time curve
    line2 = ax4_twin.plot(baseline_data['bits'], baseline_data['avg_time'], 
                          marker='o', linewidth=2.5, markersize=8, color='#3498db', 
                          label='Attack Time (seconds)', zorder=2)
    ax4_twin.set_ylabel('Average Attack Time (seconds)', fontsize=12, fontweight='bold', color='#3498db')
    ax4_twin.tick_params(axis='y', labelcolor='#3498db')
    ax4_twin.set_yscale('log')
    
    ax4.set_title('Dual Perspective: ASR vs Attack Time', fontsize=14, fontweight='bold')
    ax4.grid(True, alpha=0.3, linestyle='--')
    
    # Combine legends
    lines = line1 + line2
    labels = [l.get_label() for l in lines]
    ax4.legend(lines, labels, loc='upper right', fontsize=10)
    
    # ========== Subplot 5: Security Margin Analysis ==========
    ax5 = plt.subplot(2, 3, 5)
    bits_range = baseline_data['bits']
    security_margin = [100 - asr for asr in baseline_data['asr']]
    
    colors_security = ['#e74c3c' if sm < 50 else '#f39c12' if sm < 100 else '#2ecc71' 
                       for sm in security_margin]
    bars5 = ax5.bar(range(len(bits_range)), security_margin, 
                     color=colors_security, alpha=0.7, edgecolor='black', linewidth=1.5)
    ax5.axhline(y=100, color='green', linestyle='--', linewidth=2, alpha=0.5, label='Fully Secure')
    ax5.set_xlabel('Modulus Bit Length', fontsize=12, fontweight='bold')
    ax5.set_ylabel('Security Margin (%)', fontsize=12, fontweight='bold')
    ax5.set_title('Security Margin Analysis (Threshold: 112→128 bits)', fontsize=14, fontweight='bold')
    ax5.set_xticks(range(len(bits_range)))
    ax5.set_xticklabels(bits_range)
    ax5.set_ylim(0, 110)
    ax5.grid(axis='y', alpha=0.3, linestyle='--')
    ax5.legend(fontsize=10)
    
    # Mark the threshold point
    ax5.annotate('Security\nThreshold', xy=(4, 100), xytext=(3.5, 70),
                arrowprops=dict(arrowstyle='->', color='red', lw=2),
                fontsize=11, fontweight='bold', color='red')
    
    # Add value labels
    for i, (bar, margin) in enumerate(zip(bars5, security_margin)):
        height = bar.get_height()
        ax5.text(bar.get_x() + bar.get_width()/2., height + 2,
                f'{margin:.0f}%',
                ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    # ========== Subplot 6: Attack Complexity Growth Rate ==========
    ax6 = plt.subplot(2, 3, 6)
    
    # Calculate relative growth multiplier (relative to 64-bit)
    relative_time = [t / baseline_data['avg_time'][0] for t in baseline_data['avg_time']]
    
    ax6.bar(range(len(bits_range)), relative_time, 
            color='#9b59b6', alpha=0.7, edgecolor='black', linewidth=1.5)
    ax6.set_xlabel('Modulus Bit Length', fontsize=12, fontweight='bold')
    ax6.set_ylabel('Relative Time Multiplier (vs 64-bit)', fontsize=12, fontweight='bold')
    ax6.set_title('Attack Complexity Growth Multiplier', fontsize=14, fontweight='bold')
    ax6.set_xticks(range(len(bits_range)))
    ax6.set_xticklabels(bits_range)
    ax6.set_yscale('log')
    ax6.grid(axis='y', alpha=0.3, which='both', linestyle='--')
    
    # Add value labels
    for i, (x, y) in enumerate(zip(range(len(bits_range)), relative_time)):
        if y < 100:
            label = f'{y:.1f}×'
        else:
            label = f'{y:.0f}×'
        ax6.text(x, y, label, ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    plt.tight_layout()
    
    # Save figure
    output_file = 'test_results/experiment_results_visualization.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Chart saved to: {output_file}")
    
    plt.show()

def create_summary_table():
    """Create data summary table"""
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.axis('tight')
    ax.axis('off')
    
    # Prepare table data
    table_data = [
        ['Bit Length', 'ASR (%)', 'Success/Total', 'Avg Time (sec)', 'Relative to 64-bit', 'Security Assessment']
    ]
    
    for i, bits in enumerate(baseline_data['bits']):
        asr = baseline_data['asr'][i]
        success = baseline_data['success'][i]
        total = baseline_data['total'][i]
        time = baseline_data['avg_time'][i]
        relative = time / baseline_data['avg_time'][0]
        
        if asr == 100:
            assessment = 'Highly Insecure'
        elif asr > 50:
            assessment = 'Partial Risk'
        else:
            assessment = 'Secure'
        
        table_data.append([
            f'{bits}',
            f'{asr:.1f}',
            f'{success}/{total}',
            f'{time:.3f}' if time < 1 else f'{time:.2f}' if time < 100 else f'{time:.0f}',
            f'{relative:.0f}×',
            assessment
        ])
    
    # Add weak_imbalanced data
    table_data.append([
        '256 (Imbalanced)',
        '100.0',
        '10/10',
        '4.85',
        f'{weak_imbalanced_256["avg_time"] / baseline_data["avg_time"][0]:.0f}×',
        'Highly Insecure'
    ])
    
    # Create table
    table = ax.table(cellText=table_data, cellLoc='center', loc='center',
                     colWidths=[0.12, 0.12, 0.15, 0.18, 0.18, 0.25])
    
    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1, 2.5)
    
    # Set header style
    for i in range(6):
        cell = table[(0, i)]
        cell.set_facecolor('#3498db')
        cell.set_text_props(weight='bold', color='white', fontsize=12)
    
    # Set data row style
    for i in range(1, len(table_data)):
        for j in range(6):
            cell = table[(i, j)]
            if j == 5:  # Security assessment column
                if 'Highly Insecure' in table_data[i][j]:
                    cell.set_facecolor('#ffcccc')
                elif 'Partial Risk' in table_data[i][j]:
                    cell.set_facecolor('#fff4cc')
                else:
                    cell.set_facecolor('#ccffcc')
            else:
                cell.set_facecolor('#f0f0f0' if i % 2 == 0 else 'white')
    
    plt.title('RSA Pollard\'s rho Attack Experiment Results Summary', 
             fontsize=16, fontweight='bold', pad=20)
    
    # Save table
    output_file = 'test_results/experiment_results_table.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Data table saved to: {output_file}")
    
    plt.show()

def print_summary():
    """Print text summary"""
    print("\n" + "="*70)
    print("RSA Pollard's rho Attack Experiment - Key Findings Summary")
    print("="*70)
    
    print("\n【Experimental Conclusions】")
    print("1. Small Moduli are Vulnerable:")
    print("   • 64/80/96-bit: ASR=100%, crackable in milliseconds to seconds")
    print("   • 112-bit: ASR=80%, security threshold boundary emerges")
    
    print("\n2. Security Threshold:")
    print("   • 128-bit becomes critical threshold: ASR drops to 0%")
    print("   • Attack time surges from 617s (112-bit) to 2503s (128-bit)")
    
    print("\n3. Large Moduli Provide Effective Defense:")
    print("   • 256/512-bit baseline: ASR=0%, unbreakable within experimental limits")
    
    print("\n4. Fatal Weakness of Imbalanced Moduli:")
    print("   • 256-bit imbalanced (p≈40-bit): ASR=100%, only 4.8 seconds!")
    print("   • Compare to 256-bit balanced: ASR=0%, still unbreakable after 4656s")
    print("   • **Core Lesson: Security depends on smallest prime factor, not total bit length**")
    
    print("\n5. Attack Complexity Growth:")
    print(f"   • 128-bit vs 64-bit: {baseline_data['avg_time'][4]/baseline_data['avg_time'][0]:.0f}× time")
    print(f"   • 512-bit vs 64-bit: {baseline_data['avg_time'][6]/baseline_data['avg_time'][0]:.0f}× time")
    
    print("\n【Security Recommendations】")
    print("✓ Use moduli of at least 128 bits")
    print("✓ Ensure p and q are balanced (similar bit lengths)")
    print("✓ Recommend 2048 bits or more for practical applications")
    print("="*70 + "\n")

if __name__ == "__main__":
    print("Generating RSA attack experiment visualizations...")
    print("-" * 70)
    
    # Generate main charts
    create_visualizations()
    
    # Generate data summary table
    create_summary_table()
    
    # Print text summary
    print_summary()
    
    print("All visualizations completed!")

