import matplotlib.pyplot as plt
import numpy as np

# --- 数据准备 ---
# 实验一 (Baseline): 攻击成功率 100% (来自你的 Week 2 日志)
# 实验二 (Defended): 攻击成功率 0% (来自你的 Week 3 日志)
labels = ['实验一: 基础 D-H (Baseline)', '实验二: D-H + PSK/HMAC (Defended)']
success_rates = [100, 0]

# --- 开始绘图 ---
plt.rcParams['font.sans-serif'] = ['SimHei'] # 用来正常显示中文标签
plt.rcParams['axes.unicode_minus'] = False # 用来正常显示负号

fig, ax = plt.subplots(figsize=(10, 6))

colors = ['#D9534F', '#5CB85C'] # 红色代表攻击成功，绿色代表防御成功
bars = ax.bar(labels, success_rates, color=colors, width=0.5)

# --- 美化图表 ---
ax.set_ylabel('MITM 攻击成功率 (%)', fontsize=12)
ax.set_title('D-H 中间人攻击 (MITM) 与防御效果对比', fontsize=16, pad=20)
ax.set_ylim(0, 110) # 顶部留出空间
ax.grid(axis='y', linestyle='--', alpha=0.7)

# 在条形图上显示百分比
for bar in bars:
    height = bar.get_height()
    ax.annotate(f'{height}%',
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3),  # 3 points vertical offset
                textcoords="offset points",
                ha='center', va='bottom', fontsize=12)

# 保存图表
output_filename = 'dh_comparison_chart.png'
plt.savefig(output_filename)

print(f"对比图已成功保存为: {output_filename}")

# 可选：显示图表
# plt.show()