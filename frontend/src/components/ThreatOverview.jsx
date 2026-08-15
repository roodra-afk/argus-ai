import { useEffect, useState } from "react";
import { ShieldAlert, ShieldCheck, ShieldX, Activity } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";

export default function ThreatOverview({ refreshTrigger }) {
    const [stats, setStats] = useState(null);
    const [error, setError] = useState(false);

    async function loadStats() {
        try {
            const response = await fetch(
                "http://localhost:8000/api/v1/analysis/stats"
            );

            if (!response.ok) {
                throw new Error("Failed to load statistics");
            }

            const data = await response.json();

            setStats(data);
            setError(false);
        } catch (error) {
            console.error(error);
            setError(true);
        }
    }

    useEffect(() => {
        loadStats();
    }, [refreshTrigger]);

    if (error) {
        return null;
    }

    if (!stats) {
        return (
            <div className="mb-8 grid grid-cols-1 gap-4 md:grid-cols-4">
                {[1, 2, 3, 4].map((item) => (
                    <Card
                        key={item}
                        className="border border-slate-800 bg-slate-900"
                    >
                        <CardContent className="p-6">
                            <div className="h-4 w-24 animate-pulse rounded bg-slate-800" />
                            <div className="mt-4 h-8 w-16 animate-pulse rounded bg-slate-800" />
                        </CardContent>
                    </Card>
                ))}
            </div>
        );
    }

    const cards = [
        {
            label: "Total Analyses",
            value: stats.total,
            icon: Activity,
            valueClass: "text-white",
        },
        {
            label: "Malicious",
            value: stats.malicious,
            icon: ShieldX,
            valueClass: "text-red-400",
        },
        {
            label: "Suspicious",
            value: stats.suspicious,
            icon: ShieldAlert,
            valueClass: "text-yellow-400",
        },
        {
            label: "Benign",
            value: stats.benign,
            icon: ShieldCheck,
            valueClass: "text-emerald-400",
        },
    ];

    return (
        <section className="mb-8">
            <div className="mb-4">
                <h2 className="text-xl font-semibold text-white">
                    Threat Overview
                </h2>

                <p className="mt-1 text-sm text-slate-500">
                    Summary of analyzed samples.
                </p>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
                {cards.map((card) => {
                    const Icon = card.icon;

                    return (
                        <Card
                            key={card.label}
                            className="border border-slate-800 bg-slate-900 shadow-lg"
                        >
                            <CardContent className="p-6">
                                <div className="flex items-center justify-between">
                                    <p className="text-sm text-slate-400">
                                        {card.label}
                                    </p>

                                    <Icon className="h-5 w-5 text-slate-500" />
                                </div>

                                <p
                                    className={`mt-3 text-3xl font-bold ${card.valueClass}`}
                                >
                                    {card.value}
                                </p>
                            </CardContent>
                        </Card>
                    );
                })}
            </div>

            <Card className="mt-4 border border-slate-800 bg-slate-900 shadow-lg">
                <CardContent className="flex items-center justify-between p-5">
                    <div>
                        <p className="text-sm text-slate-400">
                            Average Risk Score
                        </p>

                        <p className="mt-1 text-2xl font-bold text-white">
                            {stats.average_risk}/100
                        </p>
                    </div>

                    <div className="text-right text-xs text-slate-500">
                        Across all analyzed samples
                    </div>
                </CardContent>
            </Card>
        </section>
    );
}
