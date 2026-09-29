#!/usr/bin/env python3
import matplotlib.pyplot as plt

files = [10, 50, 200, 500]
reachability = [0.002, 0.010, 0.040, 0.095]
apply_verify = [0.359, 1.606, 6.320, 16.034]

fig, ax = plt.subplots(figsize=(12.8, 6.4), dpi=100)
ax.plot(
    files,
    reachability,
    marker="o",
    markersize=8,
    linewidth=2.5,
    color="#2E86AB",
    label="Reachability scan",
)
ax.plot(
    files,
    apply_verify,
    marker="s",
    markersize=8,
    linewidth=2.5,
    color="#C73E1D",
    label="Apply + verify",
)
ax.text(510, 0.095, "  95ms", color="#2E86AB", fontsize=11, fontweight="bold", va="center")
ax.text(510, 16.034, "  16s", color="#C73E1D", fontsize=11, fontweight="bold", va="center")
ax.set_yscale("log")
ax.set_xscale("log")
ax.set_xlabel("Repository size (files)", fontsize=12)
ax.set_ylabel("Seconds (log scale)", fontsize=12)
ax.set_title("Where the time actually goes", fontsize=15, fontweight="bold", pad=15)
ax.legend(loc="upper left", fontsize=11, frameon=False)
ax.grid(True, which="both", alpha=0.35, linewidth=0.6)
ax.set_xticks(files)
ax.set_xticklabels([str(f) for f in files])
ax.set_xlim(8, 700)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
plt.tight_layout()
plt.savefig("profiling_featured.png", dpi=100, bbox_inches="tight")
print("Wrote profiling_featured.png")
plt.close()

fig, ax = plt.subplots(figsize=(12, 7), dpi=100)
ax.plot(
    files,
    reachability,
    marker="o",
    markersize=9,
    linewidth=2.5,
    color="#2E86AB",
    label="Reachability scan",
)
ax.plot(
    files,
    apply_verify,
    marker="s",
    markersize=9,
    linewidth=2.5,
    color="#C73E1D",
    label="Apply + verify",
)
ax.text(520, 0.095, "95ms", color="#2E86AB", fontsize=11, fontweight="bold", va="center")
ax.text(520, 16.034, "16s", color="#C73E1D", fontsize=11, fontweight="bold", va="center")
ax.set_yscale("log")
ax.set_xscale("log")
ax.set_xlabel("Repository size (files)", fontsize=12)
ax.set_ylabel("Seconds (log scale)", fontsize=12)
ax.set_title(
    "Reachability stays flat. Apply-and-verify scales linearly.",
    fontsize=14,
    fontweight="bold",
    pad=15,
)
ax.legend(loc="upper left", fontsize=11, frameon=False)
ax.grid(True, which="both", alpha=0.35, linewidth=0.6)
ax.set_xticks(files)
ax.set_xticklabels([str(f) for f in files])
ax.set_xlim(8, 700)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
plt.tight_layout()
plt.savefig("profiling_full.png", dpi=100, bbox_inches="tight")
print("Wrote profiling_full.png")
plt.close()
