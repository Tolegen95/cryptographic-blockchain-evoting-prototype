import csv
import os


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(ROOT_DIR, "benchmarks", "output")
RESULTS_CSV = os.path.join(OUTPUT_DIR, "benchmark_results.csv")
COMPARISON_CSV = os.path.join(OUTPUT_DIR, "benchmark_comparison.csv")
LATENCY_SVG = os.path.join(OUTPUT_DIR, "benchmark_latency.svg")
COMPARISON_SVG = os.path.join(OUTPUT_DIR, "benchmark_threshold_overhead.svg")


def load_rows(path):
    with open(path, "r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _points(rows, value_key, width=460, height=220, padding=28):
    values = [float(row[value_key]) for row in rows]
    x_values = [float(row["voter_count"]) for row in rows]
    min_x = min(x_values)
    max_x = max(x_values)
    min_y = min(values)
    max_y = max(values)
    x_spread = (max_x - min_x) or 1.0
    y_spread = (max_y - min_y) or 1.0
    points = []
    for x_value, y_value in zip(x_values, values):
        px = padding + ((x_value - min_x) / x_spread) * (width - (padding * 2))
        py = height - padding - ((y_value - min_y) / y_spread) * (height - (padding * 2))
        points.append((px, py, x_value, y_value))
    return points


def build_latency_svg(rows):
    cast_points = _points(rows, "cast_mean")
    mine_points = _points(rows, "mine_mean")
    homomorphic_points = _points(rows, "homomorphic_results_time")
    width = 460
    height = 220
    padding = 28

    def polyline(points):
        return " ".join("{:.2f},{:.2f}".format(px, py) for px, py, _, _ in points)

    labels = []
    for px, _, voter_count, _ in cast_points:
        labels.append(
            '<text x="{:.2f}" y="205" font-size="11" text-anchor="middle" fill="#4c5a58">{}</text>'.format(
                px, int(voter_count)
            )
        )

    return """<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
<rect width="100%" height="100%" fill="#fffdf8"/>
<line x1="{p}" y1="{p}" x2="{p}" y2="{y2}" stroke="#a49f93" stroke-width="1"/>
<line x1="{p}" y1="{y2}" x2="{x2}" y2="{y2}" stroke="#a49f93" stroke-width="1"/>
<text x="{p}" y="18" font-size="13" fill="#203331">Latency by voter count</text>
<polyline fill="none" stroke="#1f5c57" stroke-width="3" points="{cast}"/>
<polyline fill="none" stroke="#b8793f" stroke-width="3" points="{mine}"/>
<polyline fill="none" stroke="#6c7f8f" stroke-width="3" points="{homo}"/>
{labels}
<text x="40" y="30" font-size="11" fill="#1f5c57">cast</text>
<text x="80" y="30" font-size="11" fill="#b8793f">mine</text>
<text x="120" y="30" font-size="11" fill="#6c7f8f">threshold tally</text>
</svg>""".format(
        w=width,
        h=height,
        p=padding,
        y2=height - padding,
        x2=width - padding,
        cast=polyline(cast_points),
        mine=polyline(mine_points),
        homo=polyline(homomorphic_points),
        labels="".join(labels),
    )


def build_comparison_svg(rows):
    width = 460
    height = 220
    padding = 28
    bar_area = width - (padding * 2)
    bar_gap = 18
    bar_width = max(18, (bar_area - (bar_gap * (len(rows) - 1))) / max(1, len(rows)))
    max_value = max(float(row["absolute_overhead"]) for row in rows) or 1.0
    bars = []
    labels = []
    for index, row in enumerate(rows):
        value = float(row["absolute_overhead"])
        x = padding + index * (bar_width + bar_gap)
        bar_height = (value / max_value) * (height - (padding * 2) - 18)
        y = height - padding - bar_height
        bars.append(
            '<rect x="{:.2f}" y="{:.2f}" width="{:.2f}" height="{:.2f}" fill="#2f6f69"/>'.format(
                x, y, bar_width, bar_height
            )
        )
        labels.append(
            '<text x="{:.2f}" y="205" font-size="11" text-anchor="middle" fill="#4c5a58">{}</text>'.format(
                x + (bar_width / 2), int(float(row["voter_count"]))
            )
        )
    return """<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
<rect width="100%" height="100%" fill="#fffdf8"/>
<line x1="{p}" y1="{p}" x2="{p}" y2="{y2}" stroke="#a49f93" stroke-width="1"/>
<line x1="{p}" y1="{y2}" x2="{x2}" y2="{y2}" stroke="#a49f93" stroke-width="1"/>
<text x="{p}" y="18" font-size="13" fill="#203331">Threshold overhead over baseline tally</text>
{bars}
{labels}
</svg>""".format(
        w=width,
        h=height,
        p=padding,
        y2=height - padding,
        x2=width - padding,
        bars="".join(bars),
        labels="".join(labels),
    )


def main():
    results_rows = load_rows(RESULTS_CSV)
    comparison_rows = load_rows(COMPARISON_CSV)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(LATENCY_SVG, "w", encoding="utf-8") as handle:
        handle.write(build_latency_svg(results_rows))
    with open(COMPARISON_SVG, "w", encoding="utf-8") as handle:
        handle.write(build_comparison_svg(comparison_rows))
    print("Wrote {}".format(LATENCY_SVG))
    print("Wrote {}".format(COMPARISON_SVG))


if __name__ == "__main__":
    main()
