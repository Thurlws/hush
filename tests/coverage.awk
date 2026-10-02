# Turns gcov -n output into one line per source file and a total
/^File 'src\// { file = substr($2, 2, length($2) - 2); next }
/^File / { file = ""; next }
file && /^Lines executed:/ {
    split($2, a, ":")
    pct = a[2] + 0
    n = $4
    printf "%-14s %5.1f%% of %4d lines\n", file, pct, n
    hit += pct * n / 100
    total += n
    file = ""
}
END { printf "%-14s %5.1f%% of %4d lines\n", "total", 100 * hit / total, total }
