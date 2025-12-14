export function formatTimestamp(ts) {
    if (!ts) return "-";

    const normalized = ts.replace(
        /\.(\d{3})\d+/,
        ".$1"
    );

    const date = new Date(normalized);

    if (isNaN(date.getTime())) return ts;

    return date.toLocaleString("tr-TR", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });
}
