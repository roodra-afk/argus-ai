import {
    AlertTriangle,
    CheckCircle2,
    Code2,
    FileCode2,
    ShieldAlert,
} from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function PEInfoCard({ peInfo, mitreInfo }) {
    if (!peInfo) return null;

    function getEntropyLevel(entropy) {
        if (entropy >= 7.5) {
            return {
                label: "Very High",
                text: "text-red-400",
                bar: "bg-red-500",
            };
        }

        if (entropy >= 6.5) {
            return {
                label: "High",
                text: "text-yellow-400",
                bar: "bg-yellow-500",
            };
        }

        if (entropy >= 4) {
            return {
                label: "Normal",
                text: "text-blue-400",
                bar: "bg-blue-500",
            };
        }

        return {
            label: "Low",
            text: "text-emerald-400",
            bar: "bg-emerald-500",
        };
    }

    function getPermissionClass(enabled, type) {
        if (!enabled) {
            return "border-slate-800 bg-slate-950 text-slate-700";
        }

        if (type === "execute") {
            return "border-red-500/30 bg-red-950/40 text-red-300";
        }

        if (type === "write") {
            return "border-yellow-500/30 bg-yellow-950/40 text-yellow-300";
        }

        return "border-blue-500/30 bg-blue-950/40 text-blue-300";
    }

    return (
        <Card className="mt-8 border border-slate-800 bg-slate-900 shadow-xl">
            <CardContent className="p-0">
                {/* Header */}
                <div className="border-b border-slate-800 bg-slate-950/70 px-8 py-7">
                    <div className="flex items-center gap-3">
                        <FileCode2 className="h-6 w-6 text-purple-400" />

                        <div>
                            <p className="text-xs font-medium uppercase tracking-widest text-slate-500">
                                Static Analysis
                            </p>

                            <h2 className="mt-1 text-2xl font-bold text-white">
                                PE Information
                            </h2>
                        </div>
                    </div>
                </div>

                {/* PE Overview */}
                <div className="grid gap-px border-b border-slate-800 bg-slate-800 sm:grid-cols-2 lg:grid-cols-3">
                    <div className="bg-slate-900 p-6">
                        <p className="text-xs uppercase tracking-widest text-slate-500">
                            Architecture
                        </p>

                        <p className="mt-2 text-lg font-semibold text-white">
                            {peInfo.architecture}
                        </p>
                    </div>

                    <div className="bg-slate-900 p-6">
                        <p className="text-xs uppercase tracking-widest text-slate-500">
                            Sections
                        </p>

                        <p className="mt-2 text-lg font-semibold text-white">
                            {peInfo.section_count}
                        </p>
                    </div>

                    <div className="bg-slate-900 p-6">
                        <p className="text-xs uppercase tracking-widest text-slate-500">
                            Entry Point
                        </p>

                        <p className="mt-2 font-mono text-sm text-slate-300">
                            {peInfo.entry_point}
                        </p>
                    </div>

                    <div className="bg-slate-900 p-6">
                        <p className="text-xs uppercase tracking-widest text-slate-500">
                            Imported Functions
                        </p>

                        <p className="mt-2 text-lg font-semibold text-white">
                            {peInfo.packer.import_count}
                        </p>
                    </div>

                    <div className="bg-slate-900 p-6">
                        <p className="text-xs uppercase tracking-widest text-slate-500">
                            Suspicious APIs
                        </p>

                        <p
                            className={`mt-2 text-lg font-semibold ${
                                peInfo.suspicious_apis.length > 0
                                    ? "text-red-400"
                                    : "text-emerald-400"
                            }`}
                        >
                            {peInfo.suspicious_apis.length}
                        </p>
                    </div>

                    <div className="bg-slate-900 p-6">
                        <p className="text-xs uppercase tracking-widest text-slate-500">
                            Packer Indicators
                        </p>

                        <p
                            className={`mt-2 font-semibold ${
                                peInfo.packer.detected
                                    ? "text-red-400"
                                    : "text-emerald-400"
                            }`}
                        >
                            {peInfo.packer.detected
                                ? "Indicators Found"
                                : "None Detected"}
                        </p>
                    </div>
                </div>

                <div className="space-y-10 p-8">
                    {/* Imported DLLs */}
                    {peInfo.dlls && peInfo.dlls.length > 0 && (
                        <section>
                            <div className="flex items-center gap-3">
                                <Code2 className="h-5 w-5 text-blue-400" />

                                <div>
                                    <h3 className="text-lg font-semibold text-white">
                                        Imported DLLs
                                    </h3>

                                    <p className="text-sm text-slate-500">
                                        Libraries referenced by the executable.
                                    </p>
                                </div>
                            </div>

                            <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                                {peInfo.dlls.map((dll) => (
                                    <div
                                        key={dll}
                                        className="rounded-lg border border-slate-800 bg-slate-950 px-4 py-3 font-mono text-xs text-slate-300"
                                    >
                                        {dll}
                                    </div>
                                ))}
                            </div>
                        </section>
                    )}

                    {/* Suspicious APIs */}
                    <section>
                        <div className="flex items-center gap-3">
                            <ShieldAlert className="h-5 w-5 text-red-400" />

                            <div>
                                <h3 className="text-lg font-semibold text-white">
                                    Suspicious APIs
                                </h3>

                                <p className="text-sm text-slate-500">
                                    APIs identified by the static analysis
                                    pipeline.
                                </p>
                            </div>
                        </div>

                        {peInfo.suspicious_apis.length > 0 ? (
                            <div className="mt-4 flex flex-wrap gap-2">
                                {peInfo.suspicious_apis.map((api) => (
                                    <Badge
                                        key={api}
                                        className="border border-red-500/30 bg-red-950/40 px-3 py-1.5 font-mono text-xs text-red-300 hover:bg-red-950/40"
                                    >
                                        {api}
                                    </Badge>
                                ))}
                            </div>
                        ) : (
                            <div className="mt-4 flex items-center gap-2 rounded-lg border border-emerald-500/20 bg-emerald-950/20 p-4 text-sm text-emerald-300">
                                <CheckCircle2 className="h-4 w-4" />
                                No suspicious APIs identified.
                            </div>
                        )}
                    </section>

                    {/* Packer Analysis */}
                    <section>
                        <div className="flex items-center gap-3">
                            {peInfo.packer.detected ? (
                                <AlertTriangle className="h-5 w-5 text-red-400" />
                            ) : (
                                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                            )}

                            <div>
                                <h3 className="text-lg font-semibold text-white">
                                    Packer Analysis
                                </h3>

                                <p className="text-sm text-slate-500">
                                    Heuristic indicators associated with
                                    packing or obfuscation.
                                </p>
                            </div>
                        </div>

                        <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-5">
                            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                                <div>
                                    <p className="text-xs uppercase tracking-widest text-slate-500">
                                        Assessment
                                    </p>

                                    <p
                                        className={`mt-1 font-semibold ${
                                            peInfo.packer.detected
                                                ? "text-red-400"
                                                : "text-emerald-400"
                                        }`}
                                    >
                                        {peInfo.packer.detected
                                            ? "Packer indicators detected"
                                            : "No packer indicators detected"}
                                    </p>
                                </div>

                                <div className="text-left sm:text-right">
                                    <p className="text-xs uppercase tracking-widest text-slate-500">
                                        Import Count
                                    </p>

                                    <p className="mt-1 font-mono text-lg text-white">
                                        {peInfo.packer.import_count}
                                    </p>
                                </div>
                            </div>

                            {peInfo.packer.reasons.length > 0 && (
                                <div className="mt-5 border-t border-slate-800 pt-5">
                                    <p className="text-xs uppercase tracking-widest text-slate-500">
                                        Detection Reasons
                                    </p>

                                    <ul className="mt-3 space-y-2">
                                        {peInfo.packer.reasons.map(
                                            (reason, index) => (
                                                <li
                                                    key={index}
                                                    className="flex gap-2 text-sm text-red-300"
                                                >
                                                    <span>•</span>
                                                    <span>{reason}</span>
                                                </li>
                                            )
                                        )}
                                    </ul>
                                </div>
                            )}
                        </div>
                    </section>

                    {/* Section Analysis */}
                    <section>
                        <div>
                            <h3 className="text-lg font-semibold text-white">
                                Section Analysis
                            </h3>

                            <p className="mt-1 text-sm text-slate-500">
                                PE section structure, entropy and memory
                                permissions.
                            </p>
                        </div>

                        <div className="mt-4 overflow-hidden rounded-xl border border-slate-800">
                            <div className="hidden grid-cols-[1.2fr_1fr_1fr_1.4fr] border-b border-slate-800 bg-slate-950 px-5 py-3 text-xs uppercase tracking-widest text-slate-500 md:grid">
                                <span>Section</span>
                                <span>Size</span>
                                <span>Entropy</span>
                                <span>Permissions</span>
                            </div>

                            <div className="divide-y divide-slate-800">
                                {peInfo.sections.map((section) => {
                                    const entropy = getEntropyLevel(
                                        section.entropy
                                    );

                                    return (
                                        <div
                                            key={section.name}
                                            className="bg-slate-900 p-5 transition-colors hover:bg-slate-800/50"
                                        >
                                            <div className="grid gap-5 md:grid-cols-[1.2fr_1fr_1fr_1.4fr] md:items-center">
                                                {/* Section */}
                                                <div>
                                                    <p className="text-xs uppercase tracking-widest text-slate-600 md:hidden">
                                                        Section
                                                    </p>

                                                    <p className="mt-1 font-mono font-semibold text-white md:mt-0">
                                                        {section.name}
                                                    </p>

                                                    {section.findings.length >
                                                        0 && (
                                                        <div className="mt-2 flex items-center gap-1.5 text-xs text-yellow-400">
                                                            <AlertTriangle className="h-3.5 w-3.5" />

                                                            {section.findings.join(
                                                                ", "
                                                            )}
                                                        </div>
                                                    )}
                                                </div>

                                                {/* Size */}
                                                <div>
                                                    <p className="text-xs uppercase tracking-widest text-slate-600 md:hidden">
                                                        Size
                                                    </p>

                                                    <div className="mt-1 text-xs text-slate-400 md:mt-0">
                                                        <span>
                                                            Virtual:{" "}
                                                            <span className="font-mono text-slate-300">
                                                                {
                                                                    section.virtual_size
                                                                }
                                                            </span>
                                                        </span>

                                                        <span className="mx-2 text-slate-700">
                                                            /
                                                        </span>

                                                        <span>
                                                            Raw:{" "}
                                                            <span className="font-mono text-slate-300">
                                                                {
                                                                    section.raw_size
                                                                }
                                                            </span>
                                                        </span>
                                                    </div>
                                                </div>

                                                {/* Entropy */}
                                                <div>
                                                    <div className="flex items-center justify-between">
                                                        <p className="text-xs uppercase tracking-widest text-slate-600 md:hidden">
                                                            Entropy
                                                        </p>

                                                        <span
                                                            className={`font-mono text-sm font-semibold ${entropy.text}`}
                                                        >
                                                            {section.entropy.toFixed(
                                                                2
                                                            )}
                                                        </span>
                                                    </div>

                                                    <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-800">
                                                        <div
                                                            className={`h-full rounded-full ${entropy.bar}`}
                                                            style={{
                                                                width: `${Math.min(
                                                                    (section.entropy /
                                                                        8) *
                                                                        100,
                                                                    100
                                                                )}%`,
                                                            }}
                                                        />
                                                    </div>

                                                    <p
                                                        className={`mt-1 text-xs ${entropy.text}`}
                                                    >
                                                        {entropy.label}
                                                    </p>
                                                </div>

                                                {/* Permissions */}
                                                <div>
                                                    <p className="text-xs uppercase tracking-widest text-slate-600 md:hidden">
                                                        Permissions
                                                    </p>

                                                    <div className="mt-2 flex gap-2 md:mt-0">
                                                        <span
                                                            className={`rounded border px-2 py-1 font-mono text-xs ${getPermissionClass(
                                                                section
                                                                    .permissions
                                                                    .read,
                                                                "read"
                                                            )}`}
                                                        >
                                                            R
                                                        </span>

                                                        <span
                                                            className={`rounded border px-2 py-1 font-mono text-xs ${getPermissionClass(
                                                                section
                                                                    .permissions
                                                                    .write,
                                                                "write"
                                                            )}`}
                                                        >
                                                            W
                                                        </span>

                                                        <span
                                                            className={`rounded border px-2 py-1 font-mono text-xs ${getPermissionClass(
                                                                section
                                                                    .permissions
                                                                    .execute,
                                                                "execute"
                                                            )}`}
                                                        >
                                                            X
                                                        </span>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </section>

                    {/* MITRE ATT&CK */}
                    {mitreInfo && mitreInfo.length > 0 && (
                        <section>
                            <div className="flex items-center gap-3">
                                <ShieldAlert className="h-5 w-5 text-purple-400" />

                                <div>
                                    <h3 className="text-lg font-semibold text-white">
                                        MITRE ATT&CK
                                    </h3>

                                    <p className="text-sm text-slate-500">
                                        Techniques inferred from observed
                                        static indicators.
                                    </p>
                                </div>
                            </div>

                            <div className="mt-4 grid gap-4 lg:grid-cols-2">
                                {mitreInfo.map((technique) => (
                                    <div
                                        key={technique.technique}
                                        className="rounded-xl border border-purple-500/20 bg-purple-950/10 p-5"
                                    >
                                        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                                            <div>
                                                <span className="font-mono text-sm font-semibold text-purple-400">
                                                    {technique.technique}
                                                </span>

                                                <h4 className="mt-1 text-base font-semibold text-white">
                                                    {technique.name}
                                                </h4>
                                            </div>

                                            <span className="w-fit rounded-full border border-slate-700 bg-slate-950 px-2.5 py-1 text-xs text-slate-400">
                                                {technique.confidence} confidence
                                            </span>
                                        </div>

                                        <div className="mt-5">
                                            <p className="text-xs uppercase tracking-widest text-slate-600">
                                                Evidence
                                            </p>

                                            <div className="mt-2 flex flex-wrap gap-2">
                                                {technique.evidence.map(
                                                    (evidence) => (
                                                        <span
                                                            key={evidence}
                                                            className="rounded-md border border-slate-800 bg-slate-950 px-2.5 py-1.5 font-mono text-xs text-slate-300"
                                                        >
                                                            {evidence}
                                                        </span>
                                                    )
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </section>
                    )}
                </div>
            </CardContent>
        </Card>
    );
}
