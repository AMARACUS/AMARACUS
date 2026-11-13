"use client";

import React, { useEffect, useState } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loader2 } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api-client";

interface AlgorithmRow {
  id: string;
  displayName?: string;
  category: string;
  family?: string;
  status: string;
  securityStatus?: string;
  quantumResistant: boolean;
  supportedOperations?: string[];
}

export default function AlgorithmRegistryPage() {
  const { activeOrg, loading: authLoading } = useAuth();
  const [rows, setRows] = useState<AlgorithmRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!activeOrg?.id) {
      setRows([]);
      return;
    }
    setLoading(true);
    setError(null);
    api.crypto
      .getAlgorithms(activeOrg.id)
      .then((res) => setRows((res?.data || []) as AlgorithmRow[]))
      .catch((err: any) => setError(err?.message || "The algorithm registry could not be loaded."))
      .finally(() => setLoading(false));
  }, [activeOrg?.id]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-editorial text-3xl font-bold text-[#1A1A1A] tracking-tight">Algorithm Registry</h1>
        <p className="text-sm text-[#636863] mt-1">
          The algorithms this platform actually implements, read live from its registry.
        </p>
      </div>

      {!authLoading && !activeOrg && (
        <div className="p-4 rounded-xl border border-dashed border-[#E9EDE7] bg-white text-xs text-[#636863]">
          Sign in to load the algorithm registry.
        </div>
      )}

      {error && (
        <div role="alert" className="p-3 rounded-lg border border-[#F2C9C9] bg-[#FDF2F2] text-xs text-[#B42318]">
          {error}
        </div>
      )}

      {loading ? (
        <div className="py-16 flex flex-col items-center justify-center text-[#767676]">
          <Loader2 className="w-6 h-6 animate-spin text-[#008031] mb-2" />
          <span className="text-xs">Loading registry…</span>
        </div>
      ) : rows.length > 0 ? (
        <Card>
          <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Cryptographic algorithms registry table">
            <table className="w-full text-xs text-left">
              <thead className="bg-[#FAF9F6] text-[#767676] border-b border-[#E9EDE7]">
                <tr>
                  <th className="px-6 py-3 font-semibold">Algorithm ID</th>
                  <th className="px-6 py-3 font-semibold">Category</th>
                  <th className="px-6 py-3 font-semibold">Operations</th>
                  <th className="px-6 py-3 font-semibold">Quantum Resistant</th>
                  <th className="px-6 py-3 font-semibold">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E9EDE7]">
                {rows.map((row) => (
                  <tr key={row.id} className="hover:bg-[#FAF9F6] transition-colors">
                    <td className="px-6 py-3.5 font-mono font-bold text-[#1A1A1A]">{row.id}</td>
                    <td className="px-6 py-3.5"><Badge variant="outline">{row.category}</Badge></td>
                    <td className="px-6 py-3.5 text-[#555555]">{(row.supportedOperations || []).join(", ") || "—"}</td>
                    <td className="px-6 py-3.5">
                      {row.quantumResistant ? (
                        <Badge variant="default">Quantum-Safe</Badge>
                      ) : (
                        <span className="text-[#8C928C]">Classical</span>
                      )}
                    </td>
                    <td className="px-6 py-3.5">
                      <Badge variant={row.status === "SUPPORTED" ? "default" : "warning"}>
                        {row.status}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ) : null}
    </div>
  );
}
