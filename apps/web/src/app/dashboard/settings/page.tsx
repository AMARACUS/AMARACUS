"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { 
  Check, 
  Loader2, 
  AlertCircle, 
  UserPlus, 
  Trash2, 
  Download, 
  ShieldCheck, 
  AlertTriangle, 
  Lock,
  Mail,
  Bell,
  Sliders,
  CheckCircle2
} from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api-client";
import { useCookieConsent } from "@/lib/cookie-consent-context";
import { ReviewCard } from "@/components/cloud/review-card";
import { SettingsLegalLinks } from "@/components/cloud/settings-legal-links";


interface MemberItem {
  id: string;
  userId: string;
  role: string;
  email: string;
  name?: string | null;
  createdAt: string;
}

export default function SettingsPage() {
  const router = useRouter();
  const { activeOrg, user, refresh, logout, requireAuth } = useAuth();
  const [orgName, setOrgName] = useState("");
  const [saving, setSaving] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Privacy & Data Portability states
  const [exporting, setExporting] = useState(false);
  const [exportSuccess, setExportSuccess] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  // Danger Zone: Account Deletion states
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deletePassword, setDeletePassword] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  // Communication & Consent Preferences states
  const [preferencesLoading, setPreferencesLoading] = useState(false);
  const [marketingEmails, setMarketingEmails] = useState(false);
  const [savingPrefs, setSavingPrefs] = useState(false);
  const [prefMessage, setPrefMessage] = useState<string | null>(null);
  const [prefError, setPrefError] = useState<string | null>(null);

  const { openSettings } = useCookieConsent();

  const loadPreferences = useCallback(async () => {
    if (!user) {
      setPreferencesLoading(false);
      return;
    }
    setPreferencesLoading(true);
    try {
      const res = await api.user.getPreferences();
      if (res?.preferences) {
        setMarketingEmails(Boolean(res.preferences.marketingEmails));
      }
    } catch {
      // Ignore if not loaded
    } finally {
      setPreferencesLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPreferences();
  }, [loadPreferences]);

  const handleToggleMarketing = async (newValue: boolean) => {
    if (!requireAuth("update communication preferences")) return;
    setSavingPrefs(true);
    setPrefMessage(null);
    setPrefError(null);
    try {
      await api.user.updatePreferences({ marketingEmails: newValue });
      setMarketingEmails(newValue);
      setPrefMessage(
        newValue
          ? "Consent granted for security advisories and product updates. Audit record logged."
          : "Marketing consent successfully withdrawn. Immediate suppression active across all notification systems."
      );
      setTimeout(() => setPrefMessage(null), 4000);
    } catch (err: any) {
      setPrefError(err.message || "Failed to update communication preferences.");
    } finally {
      setSavingPrefs(false);
    }
  };


  // Members state
  const [members, setMembers] = useState<MemberItem[]>([]);
  const [loadingMembers, setLoadingMembers] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("MEMBER");
  const [inviting, setInviting] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);

  useEffect(() => {
    if (activeOrg) {
      setOrgName(activeOrg.name);
    }
  }, [activeOrg]);

  const loadMembers = useCallback(async () => {
    if (!activeOrg) return;
    setLoadingMembers(true);
    try {
      const data = await api.organizations.getMembers(activeOrg.id);
      setMembers(data.members || []);
    } catch {
      // Ignore if not permitted
    } finally {
      setLoadingMembers(false);
    }
  }, [activeOrg]);

  useEffect(() => {
    loadMembers();
  }, [loadMembers]);

  const handleSave = async () => {
    if (!activeOrg || !orgName.trim()) return;
    setSaving(true);
    setSaveError(null);
    try {
      await api.organizations.update(activeOrg.id, { name: orgName.trim() });
      await refresh();
      setSavedSuccess(true);
      setTimeout(() => setSavedSuccess(false), 2500);
    } catch (err: any) {
      setSaveError(err.message || "Failed to update organization name.");
    } finally {
      setSaving(false);
    }
  };

  const handleInviteMember = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeOrg || !inviteEmail.trim()) return;
    setInviting(true);
    setInviteError(null);
    try {
      await api.organizations.inviteMember(activeOrg.id, {
        email: inviteEmail.trim(),
        role: inviteRole,
      });
      setInviteEmail("");
      await loadMembers();
    } catch (err: any) {
      setInviteError(err.message || "Failed to invite member.");
    } finally {
      setInviting(false);
    }
  };

  const handleRemoveMember = async (memberId: string) => {
    if (!activeOrg) return;
    if (!confirm("Are you sure you want to remove this member?")) return;
    try {
      await api.organizations.removeMember(activeOrg.id, memberId);
      await loadMembers();
    } catch (err: any) {
      alert(err.message || "Failed to remove member.");
    }
  };

  const handleExportData = async () => {
    if (!requireAuth("export your account data")) return;
    setExporting(true);
    setExportError(null);
    try {
      const blob = await api.user.exportData();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `amaracus-data-export-${user?.id || "account"}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      setExportSuccess(true);
      setTimeout(() => setExportSuccess(false), 3500);
    } catch (err: any) {
      setExportError(err.message || "Failed to generate data export.");
    } finally {
      setExporting(false);
    }
  };

  const handleDeleteAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!requireAuth("delete account")) return;
    if (!deletePassword.trim()) {
      setDeleteError("Please enter your password to confirm deletion.");
      return;
    }
    setDeleting(true);
    setDeleteError(null);
    try {
      await api.user.deleteAccount(deletePassword.trim());
      if (logout) {
        await logout();
      } else {
        localStorage.removeItem("amaracus_session_token");
      }
      router.push("/login?deleted=true");
    } catch (err: any) {
      setDeleteError(err.message || "Failed to delete account. Please verify your password.");
      setDeleting(false);
    }
  };

  return (
    <div className="space-y-8 max-w-4xl">
      {/* Header */}
      <div className="border-b border-[#E9EDE7] pb-6">
        <h1 className="font-editorial text-3xl md:text-4xl font-bold text-[#1A1A1A] tracking-tight">
          Organization Settings
        </h1>
        <p className="text-sm text-[#636863] mt-1.5 leading-relaxed">
          Manage tenant configurations, security boundaries, and team policies for{" "}
          <span className="font-medium text-[#1A1A1A]">{activeOrg?.name}</span>.
        </p>
      </div>

      {/* General Profile */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg font-semibold">General Profile</CardTitle>
          <CardDescription className="text-xs text-[#636863]">
            Organization metadata and primary cryptographic namespace identifier.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-xs">
          {saveError && (
            <div className="p-3 rounded-lg border border-red-200 bg-red-50 text-red-700 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{saveError}</span>
            </div>
          )}

          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <label className="font-medium text-[#1A1A1A] block mb-1.5">Organization Name</label>
              <Input
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                disabled={saving}
              />
            </div>
            <div>
              <label className="font-medium text-[#1A1A1A] block mb-1.5">Organization Slug</label>
              <Input
                value={activeOrg?.slug || ""}
                disabled
                className="bg-[#FAF9F6] text-[#767676] font-mono"
              />
            </div>
          </div>

          <div className="flex items-center gap-3 pt-2">
            <Button size="sm" onClick={handleSave} disabled={saving || !orgName.trim()}>
              {saving ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Saving...
                </>
              ) : savedSuccess ? (
                <>
                  <Check className="w-3.5 h-3.5 mr-1.5 text-white" /> Saved
                </>
              ) : (
                "Save Changes"
              )}
            </Button>
            {savedSuccess && (
              <span className="text-xs text-[#008031] font-medium animate-in fade-in">
                Settings updated successfully.
              </span>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Members & RBAC */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg font-semibold">Team Members & Role-Based Access</CardTitle>
          <CardDescription className="text-xs text-[#636863]">
            Manage memberships and cryptographic access roles (OWNER, ADMIN, MEMBER).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5 text-xs">
          {/* Invite Member Form */}
          <form onSubmit={handleInviteMember} className="p-4 rounded-xl bg-[#FAF9F6] border border-[#E9EDE7] space-y-3">
            <div className="font-semibold text-[#1A1A1A] flex items-center gap-1.5">
              <UserPlus className="w-4 h-4 text-[#008031]" />
              <span>Invite New Member</span>
            </div>

            {inviteError && (
              <div className="p-2.5 rounded-lg border border-red-200 bg-red-50 text-red-700 text-xs">
                {inviteError}
              </div>
            )}

            <div className="grid sm:grid-cols-3 gap-3">
              <div className="sm:col-span-2">
                <Input
                  type="email"
                  placeholder="colleague@company.com"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  disabled={inviting}
                  required
                />
              </div>
              <div className="flex gap-2">
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value)}
                  disabled={inviting}
                  className="flex-1 h-9 rounded-lg border border-[#E9EDE7] bg-white px-3 text-xs text-[#1A1A1A] focus:border-[#008031]"
                >
                  <option value="MEMBER">MEMBER</option>
                  <option value="ADMIN">ADMIN</option>
                  <option value="OWNER">OWNER</option>
                </select>
                <Button type="submit" size="sm" disabled={inviting || !inviteEmail.trim()}>
                  {inviting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : "Invite"}
                </Button>
              </div>
            </div>
          </form>

          {/* Members Table */}
          {loadingMembers ? (
            <div className="py-6 text-center text-[#767676]">
              <Loader2 className="w-4 h-4 animate-spin text-[#008031] mx-auto mb-1" />
              <span>Loading team members...</span>
            </div>
          ) : (
            <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Team members table">
              <table className="w-full text-left">
                <thead className="bg-[#FAF9F6] text-[#767676] border-b border-[#E9EDE7]">
                  <tr>
                    <th className="px-4 py-2.5 font-semibold">User</th>
                    <th className="px-4 py-2.5 font-semibold">Role</th>
                    <th className="px-4 py-2.5 font-semibold">Joined</th>
                    <th className="px-4 py-2.5 font-semibold text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E9EDE7]">
                  {members.map((m) => (
                    <tr key={m.id} className="hover:bg-[#FAF9F6]">
                      <td className="px-4 py-3">
                        <div className="font-medium text-[#1A1A1A]">{m.name || m.email}</div>
                        <div className="text-[11px] text-[#767676]">{m.email}</div>
                      </td>
                      <td className="px-4 py-3">
                        <Badge variant={m.role === "OWNER" ? "default" : "outline"}>
                          {m.role}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-[#767676]">
                        {new Date(m.createdAt).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {m.role !== "OWNER" && (
                          <button
                            onClick={() => handleRemoveMember(m.id)}
                            title="Remove member"
                            aria-label={`Remove team member ${m.name || m.email}`}
                            className="p-1 rounded text-[#767676] hover:text-red-600 hover:bg-red-50 transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Communication & Consent Preferences (DPDPA Sec 6 / GDPR Art 7(3)) */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Mail className="w-5 h-5 text-[#008031]" />
              <CardTitle>Communication &amp; Consent Preferences</CardTitle>
            </div>
            <Badge variant="outline" className="border-emerald-300 text-emerald-800 bg-emerald-50 text-[11px]">
              DPDPA &amp; GDPR Compliant
            </Badge>
          </div>
          <CardDescription>
            Manage your consent for communications and data processing. Optional consents can be granted or withdrawn at any time.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-xs">
          {prefMessage && (
            <div className="p-3 rounded-lg border border-emerald-200 bg-emerald-50 text-emerald-800 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />
              <span>{prefMessage}</span>
            </div>
          )}

          {prefError && (
            <div className="p-3 rounded-lg border border-red-200 bg-red-50 text-red-700 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{prefError}</span>
            </div>
          )}

          <div className="divide-y divide-[#E9EDE7] border border-[#E9EDE7] rounded-xl overflow-hidden bg-white">
            {/* 1. Marketing & Technical Updates */}
            <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#FAF9F6]">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-[#1A1A1A]">Security Advisories &amp; Product Updates</span>
                  <Badge variant="outline" className={marketingEmails ? "border-emerald-300 text-emerald-800 bg-emerald-50 text-[10px]" : "border-slate-300 text-slate-700 bg-slate-50 text-[10px]"}>
                    {marketingEmails ? "Consent Active" : "Consent Withdrawn"}
                  </Badge>
                </div>
                <p className="text-[#636863] text-[11px] leading-relaxed">
                  Receive notifications regarding post-quantum cryptographic migration guides, zero-day security advisories, benchmark reports, and feature releases.
                </p>
                <p className="text-[#8C928C] text-[10px]">
                  Legal Basis: Consent (DPDPA 2023 Section 6 / GDPR Article 6(1)(a)). Unchecking immediately withdraws consent and updates the suppression list across all delivery channels.
                </p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <label className="relative inline-flex items-center cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={marketingEmails}
                    disabled={savingPrefs || preferencesLoading}
                    onChange={(e) => handleToggleMarketing(e.target.checked)}
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[#008031]"></div>
                  <span className="ml-2 text-[11px] font-medium text-[#1A1A1A]">
                    {marketingEmails ? "Enabled" : "Disabled"}
                  </span>
                </label>
              </div>
            </div>

            {/* 2. Critical Security Alerts (Contractual Delivery) */}
            <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-[#1A1A1A]">Critical Security &amp; Operational Alerts</span>
                  <Badge variant="outline" className="border-amber-300 text-amber-800 bg-amber-50 text-[10px]">
                    Contractual Necessity (Essential)
                  </Badge>
                </div>
                <p className="text-[#636863] text-[11px] leading-relaxed">
                  Mandatory operational notices including key expiration, incident warnings, rate limit breaches, and billing threshold alerts.
                </p>
                <p className="text-[#8C928C] text-[10px]">
                  Legal Basis: Contractual Necessity (GDPR Art. 6(1)(b) / DPDPA Sec. 4). Required for service operation; cannot be disabled.
                </p>
              </div>
              <div className="shrink-0 text-[11px] font-medium text-[#8C928C]">
                Always Enabled
              </div>
            </div>

            {/* 3. Cookies & Device Storage */}
            <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#FAF9F6]">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-[#1A1A1A]">Cookie &amp; Device Storage Preferences</span>
                  <Badge variant="outline" className="border-slate-300 text-slate-700 bg-slate-50 text-[10px]">
                    Configurable
                  </Badge>
                </div>
                <p className="text-[#636863] text-[11px] leading-relaxed">
                  Configure granular consent for non-essential local storage and analytics categories.
                </p>
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={openSettings}
                className="shrink-0 flex items-center gap-1.5 border-[#C8E0CF] text-[#008031] hover:bg-[#EAF3EC]"
              >
                <Sliders className="w-3.5 h-3.5" />
                Manage Cookie Preferences
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
      <ReviewCard />


      {/* Privacy, Compliance & Data Portability (DPDPA / GDPR) */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-[#008031]" />
              <CardTitle>Privacy, Compliance & Data Portability</CardTitle>
            </div>
            <Badge variant="outline" className="border-emerald-300 text-emerald-800 bg-emerald-50 text-[11px]">
              DPDPA 2023 & GDPR Aligned
            </Badge>
          </div>
          <CardDescription>
            Exercise your statutory rights under the Digital Personal Data Protection Act, 2023 and the General Data Protection Regulation (GDPR).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5 text-xs">
          <div className="p-4 rounded-xl border border-[#E9EDE7] bg-[#FAF9F6] space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h4 className="font-semibold text-[#1A1A1A]">Self-Service Data Portability (JSON Export)</h4>
                <p className="text-[#636863] mt-0.5">
                  Download a comprehensive machine-readable export of your personal profile, team memberships, API credential metadata, and cryptographic audit events.
                </p>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={handleExportData}
                disabled={exporting}
                className="shrink-0 flex items-center gap-2 border-[#C8E0CF] text-[#008031] hover:bg-[#EAF3EC]"
              >
                {exporting ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" /> Exporting...
                  </>
                ) : (
                  <>
                    <Download className="w-3.5 h-3.5" /> Export My Data (JSON)
                  </>
                )}
              </Button>
            </div>

            {exportSuccess && (
              <div className="p-3 rounded-lg border border-emerald-200 bg-emerald-50 text-emerald-800 flex items-center gap-2">
                <Check className="w-4 h-4 shrink-0 text-emerald-600" />
                <span>Your data export has been compiled and downloaded successfully.</span>
              </div>
            )}

            {exportError && (
              <div className="p-3 rounded-lg border border-red-200 bg-red-50 text-red-700 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{exportError}</span>
              </div>
            )}
          </div>

          <SettingsLegalLinks />
        </CardContent>
      </Card>

      {/* Danger Zone: Permanent Account Deletion */}
      <Card className="border-red-200 bg-red-50/20">
        <CardHeader>
          <div className="flex items-center gap-2 text-red-700">
            <AlertTriangle className="w-5 h-5 shrink-0" />
            <CardTitle className="text-red-800">Danger Zone: Permanent Account Deletion</CardTitle>
          </div>
          <CardDescription className="text-red-700/80">
            Permanently erase your identity, revoke all API credentials, and destroy tenant cryptographic keys.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-xs">
          <p className="text-[#636863] leading-relaxed">
            In compliance with the <strong>Right to Erasure</strong> (DPDPA 2023 Section 12 and GDPR Article 17), deleting your account executes permanent cryptographic erasure (crypto-shredding) of your organization&apos;s key material. This action is <strong>irreversible</strong> and cannot be undone.
          </p>

          {!showDeleteConfirm ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowDeleteConfirm(true)}
              className="border-red-300 text-red-700 hover:bg-red-50 hover:text-red-800"
            >
              <Trash2 className="w-3.5 h-3.5 mr-1.5" /> Request Account Erasure
            </Button>
          ) : (
            <form onSubmit={handleDeleteAccount} className="p-4 rounded-xl border border-red-200 bg-white space-y-3 max-w-md">
              <div className="flex items-center gap-2 text-red-800 font-semibold text-xs">
                <Lock className="w-4 h-4" />
                <span>Confirm Password for Account Erasure</span>
              </div>
              <p className="text-[11px] text-[#636863]">
                Enter your account password below to authenticate and authorize permanent erasure:
              </p>
              <Input
                type="password"
                placeholder="Enter your current password"
                value={deletePassword}
                onChange={(e) => setDeletePassword(e.target.value)}
                disabled={deleting}
                required
                className="text-xs"
              />

              {deleteError && (
                <div className="p-2.5 rounded-lg border border-red-200 bg-red-50 text-red-700 flex items-center gap-2 text-[11px]">
                  <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                  <span>{deleteError}</span>
                </div>
              )}

              <div className="flex items-center gap-2 pt-1">
                <Button
                  type="submit"
                  size="sm"
                  disabled={deleting || !deletePassword.trim()}
                  className="bg-red-700 hover:bg-red-800 text-white"
                >
                  {deleting ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> Erasing Account...
                    </>
                  ) : (
                    "Permanently Delete Account"
                  )}
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setShowDeleteConfirm(false);
                    setDeletePassword("");
                    setDeleteError(null);
                  }}
                  disabled={deleting}
                >
                  Cancel
                </Button>
              </div>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}