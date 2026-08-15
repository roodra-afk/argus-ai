import { useEffect, useMemo, useState } from "react";
import { RefreshCw, Search } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export default function AnalysisHistory({ onSelectAnalysis }) {
    const [analyses, setAnalyses] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const [search, setSearch] = useState("");
    const [verdictFilter, setVerdictFilter] = useState("All");
    const [sortBy, setSortBy] = useState("newest");

    async function loadHistory() {
        setLoading(true);
        setError(null);

        try {
            const response = await fetch(
                "http://localhost:8000/api/v1/analysis/history"
            );

            if (!response.ok) {
                throw new Error("Failed to load analysis history");
            }

            const data = await response.json();

            setAnalyses(data);
        } catch (error) {
            console.error(error);
            setError("Unable to load analysis history.");
        } finally {
            setLoading(false);
        }
    }

    async function loadAnalysis(sha256) {
        try {
            const response = await fetch(
                `http://localhost:8000/api/v1/analysis/${sha256}`
            );

            if (!response.ok) {
                throw new Error("Failed to load analysis");
            }

            const data = await response.json();

            onSelectAnalysis(data);
        } catch (error) {
            console.error(error);
            alert("Failed to load the selected analysis.");
        }
    }

    useEffect(() => {
        loadHistory();
    }, []);

    const filteredAnalyses = useMemo(() => {
        const normalizedSearch = search.trim().toLowerCase();

        const result = analyses.filter((analysis) => {
            const matchesSearch =
                !normalizedSearch ||
                analysis.filename.toLowerCase().includes(normalizedSearch) ||
                analysis.sha256.toLowerCase().includes(normalizedSearch);

            const matchesVerdict =
                verdictFilter === "All" ||
                analysis.verdict === verdictFilter;

            return matchesSearch && matchesVerdict;
        });

        return [...result].sort((a, b) => {
            switch (sortBy) {
                case "oldest":
                    return (
                        new Date(a.created_at) -
                        new Date(b.created_at)
                    );

                case "highest-risk":
                    return (b.risk_score ?? 0) - (a.risk_score ?? 0);

                case "lowest-risk":
                    return (a.risk_score ?? 0) - (b.risk_score ?? 0);

                case "newest":
                default:
                    return (
                        new Date(b.created_at) -
                        new Date(a.created_at)
                    );
            }
        });
    }, [analyses, search, verdictFilter, sortBy]);

    return (
        <Card className="mt-8 border border-slate-800 bg-slate-900 shadow-xl">
            <CardContent className="p-8">
                <div className="flex items-center justify-between">
                    <div>
                        <h2 className="text-2xl font-semibold text-white">
                            Analysis History
                        </h2>

                        <p className="mt-2 text-sm text-slate-400">
                            Previously analyzed malware samples.
                        </p>
                    </div>

                    <Button
                        variant="outline"
                        size="sm"
                        onClick={loadHistory}
                        disabled={loading}
                    >
                        <RefreshCw className="mr-2 h-4 w-4" />
                        Refresh
                    </Button>
                </div>

                {!loading && !error && analyses.length > 0 && (
                    <div className="mt-6 grid grid-cols-1 gap-3 md:grid-cols-[1fr_auto_auto]">
                        <div className="relative">
                            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />

                            <input
                                type="text"
                                value={search}
                                onChange={(e) => setSearch(e.target.value)}
                                placeholder="Search filename or SHA256..."
                                className="w-full rounded-md border border-slate-700 bg-slate-950 py-2 pl-10 pr-3 text-sm text-white outline-none placeholder:text-slate-600 focus:border-blue-500"
                            />
                        </div>

                        <select
                            value={verdictFilter}
                            onChange={(e) =>
                                setVerdictFilter(e.target.value)
                            }
                            className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500"
                        >
                            <option value="All">All Verdicts</option>
                            <option value="Benign">Benign</option>
                            <option value="Suspicious">Suspicious</option>
                            <option value="Malicious">Malicious</option>
                        </select>

                        <select
                            value={sortBy}
                            onChange={(e) => setSortBy(e.target.value)}
                            className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-blue-500"
                        >
                            <option value="newest">Newest First</option>
                            <option value="oldest">Oldest First</option>
                            <option value="highest-risk">
                                Highest Risk
                            </option>
                            <option value="lowest-risk">
                                Lowest Risk
                            </option>
                        </select>
                    </div>
                )}

                {loading ? (
                    <div className="mt-8 text-center text-slate-500">
                        Loading analysis history...
                    </div>
                ) : error ? (
                    <div className="mt-8 text-center text-red-400">
                        {error}
                    </div>
                ) : analyses.length === 0 ? (
                    <div className="mt-8 text-center text-slate-500">
                        No analyses found.
                    </div>
                ) : filteredAnalyses.length === 0 ? (
                    <div className="mt-8 rounded-lg border border-slate-800 bg-slate-950 p-8 text-center">
                        <p className="text-slate-400">
                            No analyses match your filters.
                        </p>

                        <button
                            type="button"
                            onClick={() => {
                                setSearch("");
                                setVerdictFilter("All");
                            }}
                            className="mt-3 text-sm text-blue-400 hover:text-blue-300"
                        >
                            Clear filters
                        </button>
                    </div>
                ) : (
                    <>
                        <div className="mt-4 text-xs text-slate-500">
                            Showing {filteredAnalyses.length} of{" "}
                            {analyses.length} analyses
                        </div>

                        <div className="mt-3 overflow-x-auto">
                            <table className="w-full text-left">
                                <thead>
                                    <tr className="border-b border-slate-800 text-sm text-slate-500">
                                        <th className="px-4 py-3 font-medium">
                                            Filename
                                        </th>

                                        <th className="px-4 py-3 font-medium">
                                            Verdict
                                        </th>

                                        <th className="px-4 py-3 font-medium">
                                            Risk
                                        </th>

                                        <th className="px-4 py-3 font-medium">
                                            VirusTotal
                                        </th>

                                        <th className="px-4 py-3 font-medium">
                                            Signed
                                        </th>

                                        <th className="px-4 py-3"></th>
                                    </tr>
                                </thead>

                                <tbody>
                                    {filteredAnalyses.map((analysis) => (
                                        <tr
                                            key={analysis.id}
                                            className="border-b border-slate-800/60 transition-colors hover:bg-slate-800/40"
                                        >
                                            <td className="px-4 py-4">
                                                <p className="font-medium text-white">
                                                    {analysis.filename}
                                                </p>

                                                <p className="mt-1 max-w-xs truncate font-mono text-xs text-slate-500">
                                                    {analysis.sha256}
                                                </p>
                                            </td>

                                            <td className="px-4 py-4">
                                                <span
                                                    className={
                                                        analysis.verdict ===
                                                        "Benign"
                                                            ? "text-emerald-400"
                                                            : analysis.verdict ===
                                                              "Malicious"
                                                            ? "text-red-400"
                                                            : "text-yellow-400"
                                                    }
                                                >
                                                    {analysis.verdict}
                                                </span>
                                            </td>

                                            <td className="px-4 py-4">
                                                <span className="font-mono text-white">
                                                    {analysis.risk_score}/100
                                                </span>
                                            </td>

                                            <td className="px-4 py-4 text-slate-300">
                                                {analysis.vt_detections}/
                                                {analysis.vt_total_engines}
                                            </td>

                                            <td className="px-4 py-4">
                                                <span
                                                    className={
                                                        analysis.signed
                                                            ? "text-emerald-400"
                                                            : "text-slate-500"
                                                    }
                                                >
                                                    {analysis.signed
                                                        ? "Yes"
                                                        : "No"}
                                                </span>
                                            </td>

                                            <td className="px-4 py-4 text-right">
                                                <Button
                                                    size="sm"
                                                    onClick={() =>
                                                        loadAnalysis(
                                                            analysis.sha256
                                                        )
                                                    }
                                                >
                                                    View
                                                </Button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </>
                )}
            </CardContent>
        </Card>
    );
}
