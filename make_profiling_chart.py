#!/usr/bin/env python3
import matplotlib.pyplot as plt

files = [10, 50, 200, 500]
reachability = [0.002, 0.010, 0.040, 0.095]
apply_verify = [0.359, 1.606, 6.320, 16.034]

# Featured image (1280x640)
fig, ax = plt.subplots(figsize=(12.8, 6.4), dpi=100)
ax.plot(files, reachability, marker="o", linewidth=2.5, color="#2E86AB", label="Reachability scan")
ax.plot(files, apply_verify, marker="s", linewidth=2.5, color="#C73E1D", label="Apply + verify")
ax.annotate(
    "A Python interpreter,\nstarted fresh, 500 times",
    xy=(500, 16.034),
    xytext=(300, 12),
    fontsize=11,
    color="#C73E1D",
    arrowprops=dict(arrowstyle="->", color="#C73E1D", lw=1.5),
)
ax.annotate(
    "The analysis that\nlooks expensive: 95ms",
    xy=(500, 0.095),
    xytext=(300, 3.5),
    fontsize=11,
    color="#2E86AB",
    arrowprops=dict(arrowstyle="->", color="#2E86AB", lw=1.5),
)
ax.set_xlabel("Repository size (files)", fontsize=12)
ax.set_ylabel("Seconds", fontsize=12)
ax.set_title("Where the time actually goes", fontsize=15, fontweight="bold")
ax.legend(loc="upper left", fontsize=11, frameon=False)
ax.grid(True, alpha=0.3)
ax.set_xticks(files)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
plt.tight_layout()
plt.savefig("profiling_featured.png", dpi=100, bbox_inches="tight")
print("Wrote profiling_featured.png")
plt.close()

# Full in-article version (1200x800)
fig, ax = plt.subplots(figsize=(12, 8), dpi=100)
ax.plot(files, reachability, marker="o", linewidth=2.5, color="#2E86AB", label="Reachability scan")
ax.plot(files, apply_verify, marker="s", linewidth=2.5, color="#C73E1D", label="Apply + verify")
ax.fill_between(files, reachability, apply_verify, alpha=0.08, color="#C73E1D")
ax.annotate(
    "Scales with FILE COUNT, not CVE count.\nThe tell that something mechanical\nis driving the cost.",
    xy=(500, 16.034),
    xytext=(180, 11.5),
    fontsize=11,
    color="#8B2E15",
    arrowprops=dict(arrowstyle="->", color="#8B2E15", lw=1.5),
)
ax.annotate(
    "Parses every file, resolves every import,\nwalks every function call.\nCosts 95 milliseconds at 500 files.",
    xy=(500, 0.095),
    xytext=(80, 4),
    fontsize=10,
    color="#1F5D7A",
    arrowprops=dict(arrowstyle="->", color="#1F5D7A", lw=1.5),
)
ax.set_xlabel("Repository size (files)", fontsize=13)
ax.set_ylabel("Seconds", fontsize=13)
ax.set_title(
    "Reachability stays flat. Apply-and-verify scales linearly.", fontsize=15, fontweight="bold"
)
ax.legend(loc="upper left", fontsize=12, frameon=False)
ax.grid(True, alpha=0.3)
ax.set_xticks(files)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
plt.tight_layout()
plt.savefig("profiling_full.png", dpi=100, bbox_inches="tight")
print("Wrote profiling_full.png")
plt.close()
