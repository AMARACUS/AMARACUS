"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Search, Loader2, Activity } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api-client";

interface AuditLogEntry {
  id: string;
  action: string;
  resourceType: string;
  resourceId?: string | null;
  metadata?: any;
  ipAddress?: string | null;
  actorId?: string | null;
  createdAt: string;
}

export default function AuditLogsPage() {
  const { activeOrg } = useAuth();
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [nextBefore, setNextBefore] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);

  const loadAuditLogs = useCallback(async () => {
    setLoadError(null);
    if (!activeOrg) {
      // Signed out: no organization, so no audit trail to show.
      setLogs([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const data: any = await api.audit.list(activeOrg.id, 100);
      setLogs(data.auditEvents || []);
      setNextBefore(data.nextBefore || null);
    } catch (err: any) {
      setLogs([]);
      setLoadError(err?.message || "The audit log could not be loaded.");
    } finally {
      setLoading(false);
    }
  }, [activeOrg]);

  useEffect(() => {
    loadAuditLogs();
  }, [loadAuditLogs]);

  // The API returns 100 events at a time; this fetches the next 100 older ones.
  const loadOlder = async () => {
    if (!activeOrg || !nextBefore) return;
    setLoadingMore(true);
    try {
      const data: any = await api.audit.list(activeOrg.id, 100, { before: nextBefore });
      setLogs((prev) => [...prev, ...(data.auditEvents || [])]);
      setNextBefore(data.nextBefore || null);
    } catch (err: any) {
      setLoadError(err?.message || "Older audit events could not be loaded.");
    } finally {
      setLoadingMore(false);
    }
  };

  const filteredLogs = logs.filter((log) => {
    const q = searchTerm.toLowerCase();
    const action = log.action.toLowerCase();
    const resType = (log.resourceType || "").toLowerCase();
    const resId = (log.resourceId || "").toLowerCase();
    const meta = JSON.stringify(log.metadata || {}).toLowerCase();
    const who = `${log.actorId || ""} ${log.ipAddress || ""}`.toLowerCase();
    return action.includes(q) || resType.includes(q) || resId.includes(q) || meta.includes(q) || who.includes(q);
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-editorial text-3xl font-bold text-[#1A1A1A] tracking-tight">Audit Logs</h1>
        <p className="text-sm text-[#636863] mt-1">
          Tamper-evident record of all tenant events, memberships, and cryptographic operations in{" "}
          <span className="font-medium text-[#1A1A1A]">{activeOrg?.name || "your organization"}</span>.
        </p>
      </div>

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-[#8C928C] absolute left-3 top-3" />
          <Input
            placeholder="Search by action, resource type, or identifier..."
            aria-label="Search audit records by action, resource type, or identifier"
            className="pl-9"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      {loadError && (
        <div role="alert" className="p-3 rounded-lg border border-[#F2C9C9] bg-[#FDF2F2] text-xs text-[#B42318]">
          {loadError}
        </div>
      )}

      {loading ? (
        <div className="py-20 flex flex-col items-center justify-center text-[#767676]">
          <Loader2 className="w-6 h-6 animate-spin text-[#008031] mb-2" />
          <span className="text-xs">Loading audit trail from database...</span>
        </div>
      ) : logs.length === 0 ? (
        <div className="p-12 text-center border border-dashed border-[#E9EDE7] rounded-2xl bg-white space-y-3">
          <div className="w-12 h-12 rounded-2xl bg-[#EAF3EC] text-[#008031] flex items-center justify-center mx-auto">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-[#1A1A1A]">No audit events logged</h3>
            <p className="text-xs text-[#767676] max-w-sm mx-auto mt-1">
              Events will automatically appear here as team members configure projects, environments, and credentials.
            </p>
          </div>
        </div>
      ) : (
        <Card>
          <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Audit logs table">
            <table className="w-full text-xs text-left">
              <thead className="bg-[#FAF9F6] text-[#767676] border-b border-[#E9EDE7]">
                <tr>
                  <th className="px-6 py-3 font-semibold">Timestamp</th>
                  <th className="px-6 py-3 font-semibold">Action</th>
                  <th className="px-6 py-3 font-semibold">Resource Type</th>
                  <th className="px-6 py-3 font-semibold">Resource ID</th>
                  <th className="px-6 py-3 font-semibold">By (key or user)</th>
                  <th className="px-6 py-3 font-semibold">IP address</th>
                  <th className="px-6 py-3 font-semibold">Details</th>
                  <th className="px-6 py-3 font-semibold text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E9EDE7]">
                {filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-6 py-8 text-center text-[#767676]">
                      No audit records match your search criteria.
                    </td>
                  </tr>
                ) : (
                  filteredLogs.map((row) => (
                    <tr key={row.id} className="hover:bg-[#FAF9F6] transition-colors">
                      <td className="px-6 py-3.5 font-mono text-[#767676]">
                        {new Date(row.createdAt).toLocaleString()}
                      </td>
                      <td className="px-6 py-3.5 font-semibold text-[#1A1A1A]">{row.action}</td>
                      <td className="px-6 py-3.5 text-[#555555]">{row.resourceType}</td>
                      <td className="px-6 py-3.5 font-mono text-[#008031]">
                        {row.resourceId ? `${row.resourceId.slice(0, 16)}...` : "—"}
                      </td>
                      <td className="px-6 py-3.5 font-mono text-[#555555]">{row.actorId ? `${row.actorId.slice(0, 12)}…` : "—"}</td>
                      <td className="px-6 py-3.5 font-mono text-[#555555]">{row.ipAddress || "—"}</td>
                      <td className="px-6 py-3.5 font-mono text-[#767676] max-w-xs truncate">
                        {row.metadata ? JSON.stringify(row.metadata) : "—"}
                      </td>
                      <td className="px-6 py-3.5 text-right">
                        <Badge variant="default">Recorded</Badge>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          {nextBefore && (
            <div className="p-4 border-t border-[#E9EDE7] text-center">
              <button
                type="button"
                onClick={loadOlder}
                disabled={loadingMore}
                className="text-xs font-semibold text-[#008031] underline disabled:opacity-60"
              >
                {loadingMore ? "Loading…" : "Load 100 older events"}
              </button>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}