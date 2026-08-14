import { Card, CardContent } from "@/components/ui/card";

export default function PEInfoCard({ peInfo, mitreInfo }) {
    if (!peInfo) return null;

    return (
        <Card className="mt-8 border border-slate-800 bg-slate-900 shadow-xl">
            <CardContent className="p-8">
                <h2 className="text-2xl font-semibold text-white">
                    PE Information
                </h2>

                {/* PE Overview */}
                <div className="mt-6 grid grid-cols-2 gap-6">
                    <div>
                        <p className="text-sm text-slate-400">
                            Architecture
                        </p>

                        <p className="mt-1 text-lg text-white">
                            {peInfo.architecture}
                        </p>
                    </div>

                    <div>
                        <p className="text-sm text-slate-400">
                            Sections
                        </p>

                        <p className="mt-1 text-lg text-white">
                            {peInfo.section_count}
                        </p>
                    </div>

                    <div>
                        <p className="text-sm text-slate-400">
                            Entry Point
                        </p>

                        <p className="mt-1 font-mono text-white">
                            {peInfo.entry_point}
                        </p>
                    </div>

                    <div>
                        <p className="text-sm text-slate-400">
                            Imported Functions
                        </p>

                        <p className="mt-1 text-lg text-white">
                            {peInfo.packer.import_count}
                        </p>
                    </div>

                    <div>
                        <p className="text-sm text-slate-400">
                            Packer
                        </p>

                        <p
                            className={`mt-1 font-medium ${
                                peInfo.packer.detected
                                    ? "text-red-400"
                                    : "text-emerald-400"
                            }`}
                        >
                            {peInfo.packer.detected
                                ? "Detected"
                                : "Not Detected"}
                        </p>
                    </div>

                    <div>
                        <p className="text-sm text-slate-400">
                            Suspicious APIs
                        </p>

                        <p className="mt-1 text-lg text-white">
                            {peInfo.suspicious_apis.length}
                        </p>
                    </div>
                </div>

                {/* Suspicious APIs */}
                {peInfo.suspicious_apis.length > 0 && (
                    <div className="mt-8">
                        <h3 className="text-lg font-semibold text-white">
                            Suspicious APIs
                        </h3>

                        <div className="mt-4 flex flex-wrap gap-2">
                            {peInfo.suspicious_apis.map((api) => (
                                <span
                                    key={api}
                                    className="rounded-md border border-red-900/50 bg-red-950/40 px-3 py-1.5 font-mono text-sm text-red-300"
                                >
                                    {api}
                                </span>
                            ))}
                        </div>
                    </div>
                )}

                {/* Packer Analysis */}
                <div className="mt-8">
                    <h3 className="text-lg font-semibold text-white">
                        Packer Analysis
                    </h3>

                    <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950 p-5">
                        <div className="flex items-center justify-between">
                            <span className="text-sm text-slate-400">
                                Status
                            </span>

                            <span
                                className={`font-medium ${
                                    peInfo.packer.detected
                                        ? "text-red-400"
                                        : "text-emerald-400"
                                }`}
                            >
                                {peInfo.packer.detected
                                    ? "Indicators Detected"
                                    : "No Indicators Detected"}
                            </span>
                        </div>

                        <div className="mt-3 flex items-center justify-between">
                            <span className="text-sm text-slate-400">
                                Import Count
                            </span>

                            <span className="font-mono text-white">
                                {peInfo.packer.import_count}
                            </span>
                        </div>

                        {peInfo.packer.reasons.length > 0 && (
                            <div className="mt-4">
                                <p className="text-sm text-slate-400">
                                    Detection Reasons
                                </p>

                                <ul className="mt-2 space-y-2">
                                    {peInfo.packer.reasons.map(
                                        (reason, index) => (
                                            <li
                                                key={index}
                                                className="text-sm text-red-300"
                                            >
                                                • {reason}
                                            </li>
                                        )
                                    )}
                                </ul>
                            </div>
                        )}
                    </div>
                </div>

                {/* Section Analysis */}
                <div className="mt-8">
                    <h3 className="text-lg font-semibold text-white">
                        Section Analysis
                    </h3>

                    <div className="mt-4 space-y-4">
                        {peInfo.sections.map((section) => (
                            <div
                                key={section.name}
                                className="rounded-lg border border-slate-800 bg-slate-950 p-5"
                            >
                                <div className="flex items-center justify-between">
                                    <span className="font-mono text-lg font-semibold text-white">
                                        {section.name}
                                    </span>

                                    <span className="text-sm text-slate-400">
                                        Entropy: {section.entropy}
                                    </span>
                                </div>

                                <div className="mt-4 grid grid-cols-2 gap-4">
                                    <div>
                                        <p className="text-xs text-slate-500">
                                            Virtual Size
                                        </p>

                                        <p className="mt-1 text-sm text-slate-300">
                                            {section.virtual_size}
                                        </p>
                                    </div>

                                    <div>
                                        <p className="text-xs text-slate-500">
                                            Raw Size
                                        </p>

                                        <p className="mt-1 text-sm text-slate-300">
                                            {section.raw_size}
                                        </p>
                                    </div>
                                </div>

                                <div className="mt-4 flex gap-2">
                                    <span
                                        className={`rounded px-2 py-1 text-xs ${
                                            section.permissions.read
                                                ? "bg-blue-950 text-blue-300"
                                                : "bg-slate-900 text-slate-600"
                                        }`}
                                    >
                                        R
                                    </span>

                                    <span
                                        className={`rounded px-2 py-1 text-xs ${
                                            section.permissions.write
                                                ? "bg-yellow-950 text-yellow-300"
                                                : "bg-slate-900 text-slate-600"
                                        }`}
                                    >
                                        W
                                    </span>

                                    <span
                                        className={`rounded px-2 py-1 text-xs ${
                                            section.permissions.execute
                                                ? "bg-red-950 text-red-300"
                                                : "bg-slate-900 text-slate-600"
                                        }`}
                                    >
                                        X
                                    </span>
                                </div>

                                {section.findings.length > 0 && (
                                    <div className="mt-4">
                                        <p className="text-sm text-slate-400">
                                            Findings
                                        </p>

                                        <ul className="mt-2 space-y-1">
                                            {section.findings.map(
                                                (finding, index) => (
                                                    <li
                                                        key={index}
                                                        className="text-sm text-yellow-300"
                                                    >
                                                        • {finding}
                                                    </li>
                                                )
                                            )}
                                        </ul>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </div>

                {/* MITRE ATT&CK */}
                {mitreInfo && mitreInfo.length > 0 && (
                    <div className="mt-8">
                        <h3 className="text-lg font-semibold text-white">
                            MITRE ATT&CK
                        </h3>

                        <div className="mt-4 space-y-4">
                            {mitreInfo.map((technique) => (
                                <div
                                    key={technique.technique}
                                    className="rounded-lg border border-slate-800 bg-slate-950 p-5"
                                >
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <span className="font-mono text-sm text-purple-400">
                                                {technique.technique}
                                            </span>

                                            <span className="ml-3 text-white">
                                                {technique.name}
                                            </span>
                                        </div>

                                        <span className="text-xs text-slate-400">
                                            Confidence:{" "}
                                            {technique.confidence}
                                        </span>
                                    </div>

                                    <div className="mt-3">
                                        <p className="text-xs text-slate-500">
                                            Evidence
                                        </p>

                                        <div className="mt-2 flex flex-wrap gap-2">
                                            {technique.evidence.map(
                                                (evidence) => (
                                                    <span
                                                        key={evidence}
                                                        className="rounded-md bg-slate-900 px-2 py-1 font-mono text-xs text-slate-300"
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
                    </div>
                )}
            </CardContent>
        </Card>
    );
}
