"use client";

import React, { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { 
  Shield, 
  LayoutDashboard, 
  Database, 
  Key, 
  Fingerprint, 
  Zap, 
  Activity, 
  FileCode2, 
  Settings, 
  BookOpen, 
  Menu, 
  X, 
  ChevronDown,
  Lock,
  ListChecks,
  LogOut,
  Building2,
  Check,
  Plus,
  Loader2,
  Compass,
  Cpu,
  Terminal,
  CreditCard
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Modal } from "@/components/ui/modal";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api-client";
import { useEdition } from "@/lib/edition";
import { NavItem } from "@/components/dashboard-nav-item";
import { CloudOverviewNav, CloudOperationsNav, CloudPlanWidget, GuestBannerText } from "@/components/cloud/dashboard-nav";
import { SelfHostActivationGate } from "@/components/selfhost-activation-gate";

export function DashboardShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { user, activeOrg, organizations, loading, switchOrg, logout, refresh } = useAuth();
  const { edition, status: editionStatus } = useEdition();
  const selfHosted = edition === "selfhosted";

  const [mobileOpen, setMobileOpen] = useState(false);
  const [orgDropdownOpen, setOrgDropdownOpen] = useState(false);
  const [createOrgOpen, setCreateOrgOpen] = useState(false);
  const [newOrgName, setNewOrgName] = useState("");
  const [creatingOrg, setCreatingOrg] = useState(false);
  const [orgError, setOrgError] = useState<string | null>(null);

  const dropdownRef = useRef<HTMLDivElement>(null);
  const orgTriggerRef = useRef<HTMLButtonElement>(null);
  const mobileTriggerRef = useRef<HTMLButtonElement>(null);

  const isGuest = !user;

  // Close dropdown on outside click
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setOrgDropdownOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Handle ESC key for dropdown and mobile drawer
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        if (orgDropdownOpen) {
          e.preventDefault();
          setOrgDropdownOpen(false);
          orgTriggerRef.current?.focus();
        } else if (mobileOpen) {
          e.preventDefault();
          setMobileOpen(false);
          mobileTriggerRef.current?.focus();
        }
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [orgDropdownOpen, mobileOpen]);

  const handleCreateOrg = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newOrgName.trim()) return;
    setCreatingOrg(true);
    setOrgError(null);
    try {
      const res = await api.organizations.create({ name: newOrgName.trim() });
      await refresh();
      setNewOrgName("");
      setCreateOrgOpen(false);
      setOrgDropdownOpen(false);
      if (res.organization?.id) {
        await switchOrg(res.organization.id);
      }
    } catch (err: any) {
      setOrgError(err.message || "Failed to create organization");
    } finally {
      setCreatingOrg(false);
    }
  };

  const handleLogout = async () => {
    await logout();
    router.push("/login");
  };

  if (loading || edition === "unknown") {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-[#F8F7F4] text-[#1A1A1A]">
        <div className="w-10 h-10 rounded-xl bg-[#EAF3EC] border border-[#C8E0CF] flex items-center justify-center text-[#008031] mb-4 animate-pulse">
          <Shield className="w-5 h-5 fill-[#008031]/20 stroke-[#008031]" />
        </div>
        <div className="flex items-center gap-2 text-xs text-[#767676] font-medium">
          <Loader2 className="w-3.5 h-3.5 animate-spin text-[#008031]" />
          <span>Verifying security session...</span>
        </div>
      </div>
    );
  }

  // Self-hosted installation whose licences have not been accepted yet: nothing else is shown until they are.
  if (selfHosted && editionStatus && !editionStatus.activated) {
    return <SelfHostActivationGate />;
  }

  const userInitials = user
    ? (user.name || user.email || "AU")
        .split(" ")
        .map((n) => n[0])
        .join("")
        .slice(0, 2)
        .toUpperCase()
    : "GP";

  return (
    <div className="flex min-h-screen bg-[#F8F7F4]">
      {/* Mobile Backdrop */}
      {mobileOpen && (
        <div 
          className="fixed inset-0 z-40 bg-black/20 backdrop-blur-xs md:hidden"
          onClick={() => setMobileOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Persistent Left Sidebar */}
      <aside 
        aria-label="Sidebar navigation"
        className={cn(
          "fixed inset-y-0 left-0 z-50 w-64 border-r border-[#E9EDE7] bg-white flex flex-col transition-transform duration-200 md:static md:translate-x-0 md:visible",
          mobileOpen ? "translate-x-0 visible" : "max-md:-translate-x-full max-md:invisible"
        )}
      >
        {/* Brand Header */}
        <div className="h-16 px-5 border-b border-[#E9EDE7] flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-[#EAF3EC] border border-[#C8E0CF] flex items-center justify-center text-[#008031]">
              <Shield className="w-4 h-4 fill-[#008031]/20 stroke-[#008031]" aria-hidden="true" />
            </div>
            <span className="font-editorial text-lg font-bold tracking-tight text-[#1A1A1A]">
              AMARACUS
            </span>
          </Link>
          <button 
            onClick={() => setMobileOpen(false)}
            aria-label="Close navigation menu"
            className="md:hidden p-1 rounded-md hover:bg-[#F3F2EE] text-[#767676]"
          >
            <X className="w-5 h-5" aria-hidden="true" />
          </button>
        </div>

        {/* Real Multi-Tenant Organization Switcher */}
        <div className="p-3 border-b border-[#E9EDE7] bg-[#FAF9F6] relative" ref={dropdownRef}>
          {isGuest ? (
            <div className="w-full flex items-center justify-between p-2 rounded-lg border border-[#C8E0CF] bg-[#EAF3EC]/60 text-left">
              <div className="flex items-center gap-2 min-w-0">
                <div className="w-6 h-6 rounded-md bg-[#008031] text-white flex items-center justify-center shrink-0">
                  <Shield className="w-3.5 h-3.5" />
                </div>
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-[#1A1A1A] truncate">
                    AMARACUS Sandbox
                  </div>
                  <div className="text-[10px] text-[#008031] truncate flex items-center gap-1.5 font-medium">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#008031]"></span>
                    <span className="uppercase tracking-wide">Guest Preview</span>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <button
              ref={orgTriggerRef}
              onClick={() => setOrgDropdownOpen(!orgDropdownOpen)}
              aria-haspopup="menu"
              aria-expanded={orgDropdownOpen}
              aria-controls="org-dropdown-menu"
              aria-label="Select organization"
              className="w-full flex items-center justify-between p-2 rounded-lg border border-[#E9EDE7] bg-white hover:bg-[#F8F7F4] transition-colors text-left"
            >
              <div className="flex items-center gap-2 min-w-0">
                <div className="w-6 h-6 rounded-md bg-[#EAF3EC] text-[#008031] flex items-center justify-center shrink-0">
                  <Building2 className="w-3.5 h-3.5" />
                </div>
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-[#1A1A1A] truncate">
                    {activeOrg?.name || "Select Organization"}
                  </div>
                  <div className="text-[10px] text-[#767676] truncate flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#008031]"></span>
                    <span className="uppercase font-medium tracking-wide">{activeOrg?.role || "MEMBER"}</span>
                  </div>
                </div>
              </div>
              <ChevronDown className={cn("w-3.5 h-3.5 text-[#767676] shrink-0 transition-transform", orgDropdownOpen && "rotate-180")} />
            </button>
          )}

          {/* Org Dropdown Menu */}
          {!isGuest && orgDropdownOpen && (
            <div 
              id="org-dropdown-menu"
              role="menu"
              aria-label="Organizations"
              className="absolute top-full left-3 right-3 mt-1.5 z-50 bg-white border border-[#E9EDE7] rounded-xl shadow-lg py-1.5 animate-in fade-in slide-in-from-top-1"
            >
              <div className="px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider text-[#8C928C]">
                Organizations
              </div>
              <div className="max-h-48 overflow-y-auto space-y-0.5 px-1.5" role="none">
                {organizations.map((org) => {
                  const isActive = org.id === activeOrg?.id;
                  return (
                    <button
                      key={org.id}
                      role="menuitem"
                      onClick={async () => {
                        await switchOrg(org.id);
                        setOrgDropdownOpen(false);
                        orgTriggerRef.current?.focus();
                      }}
                      className={cn(
                        "w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs transition-colors text-left",
                        isActive ? "bg-[#EAF3EC] text-[#008031] font-semibold" : "text-[#1A1A1A] hover:bg-[#F3F2EE]"
                      )}
                    >
                      <div className="truncate min-w-0">
                        <div className="truncate">{org.name}</div>
                        <div className="text-[10px] text-[#767676] font-normal">{org.role}</div>
                      </div>
                      {isActive && <Check className="w-3.5 h-3.5 text-[#008031] shrink-0" />}
                    </button>
                  );
                })}
              </div>

              <div className="border-t border-[#E9EDE7] mt-1.5 pt-1.5 px-1.5" role="none">
                <button
                  role="menuitem"
                  onClick={() => {
                    setOrgDropdownOpen(false);
                    setCreateOrgOpen(true);
                  }}
                  className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs text-[#008031] font-medium hover:bg-[#EAF3EC] transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>New Organization</span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Navigation links */}
        <div className="flex-1 overflow-y-auto py-4 px-3 space-y-5 text-sm">
          <div>
            <span className="px-2.5 text-[11px] font-bold uppercase tracking-wider text-[#8C928C]">
              Overview
            </span>
            <div className="mt-1 space-y-0.5">
              <NavItem href="/dashboard" icon={<LayoutDashboard size={16} />} label="Console Overview" currentPath={pathname} />
              {selfHosted ? (
                <NavItem href="/dashboard/billing" icon={<CreditCard size={16} />} label="Licence & Usage" currentPath={pathname} />
              ) : (
                <CloudOverviewNav pathname={pathname} />
              )}
            </div>
          </div>

          <div>
            <span className="px-2.5 text-[11px] font-bold uppercase tracking-wider text-[#8C928C]">
              Build
            </span>
            <div className="mt-1 space-y-0.5">
              <NavItem href="/dashboard/projects" icon={<Database size={16} />} label="Projects & Env" currentPath={pathname} />
              <NavItem href="/dashboard/api-keys" icon={<FileCode2 size={16} />} label="API Credentials" currentPath={pathname} />
              <NavItem href="/dashboard/api-explorer" icon={<Terminal size={16} />} label="API Explorer" currentPath={pathname} />
              <NavItem href="/dashboard/crypto" icon={<Zap size={16} />} label="Cryptography Playground" currentPath={pathname} />
            </div>
          </div>

          <div>
            <span className="px-2.5 text-[11px] font-bold uppercase tracking-wider text-[#8C928C]">
              Cryptography
            </span>
            <div className="mt-1 space-y-0.5">
              <NavItem href="/dashboard/keys" icon={<Key size={16} />} label="Key Management" currentPath={pathname} />
              <NavItem href="/dashboard/policies" icon={<Lock size={16} />} label="Cryptographic Policies" currentPath={pathname} />
              <NavItem href="/dashboard/registry" icon={<ListChecks size={16} />} label="Algorithm Registry" currentPath={pathname} />
              <NavItem href="/dashboard/pki" icon={<Fingerprint size={16} />} label="PKI & Certificates" currentPath={pathname} />
              <NavItem href="/dashboard/intelligence" icon={<Compass size={16} />} label="Cryptographic Intelligence & CBOM" currentPath={pathname} />
              <NavItem href="/dashboard/advanced" icon={<Cpu size={16} />} label="Advanced Cryptography" currentPath={pathname} />
            </div>
          </div>

          <div>
            <span className="px-2.5 text-[11px] font-bold uppercase tracking-wider text-[#8C928C]">
              Operations
            </span>
            <div className="mt-1 space-y-0.5">
              {!selfHosted && <CloudOperationsNav pathname={pathname} />}
              <NavItem href="/dashboard/audit" icon={<Activity size={16} />} label="Audit Logs" currentPath={pathname} />
              <NavItem href="/docs" icon={<BookOpen size={16} />} label="Documentation" currentPath={pathname} />
              <NavItem href="/dashboard/settings" icon={<Settings size={16} />} label="Settings" currentPath={pathname} />
            </div>
          </div>
        </div>

        {!selfHosted && <CloudPlanWidget />}

        {/* Real User Profile Footer or Guest Sign In Bar */}
        {isGuest ? (
          <div className="p-3.5 border-t border-[#E9EDE7] bg-[#FAF9F6] space-y-2.5">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded-full bg-[#EAF3EC] border border-[#C8E0CF] text-[#008031] font-semibold text-xs flex items-center justify-center shrink-0">
                GP
              </div>
              <div className="min-w-0">
                <div className="text-xs font-semibold text-[#1A1A1A] truncate">Guest Explorer</div>
                <div className="text-[11px] text-[#767676] truncate">Read-only preview</div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              <Link
                href={`/login?redirect=${encodeURIComponent(pathname)}`}
                className="py-1.5 px-2 rounded-lg border border-[#E9EDE7] bg-white hover:bg-[#F3F2EE] text-[#1A1A1A] font-medium text-[11px] text-center transition-colors"
              >
                Sign In
              </Link>
              <Link
                href={`/signup?redirect=${encodeURIComponent(pathname)}`}
                className="py-1.5 px-2 rounded-lg bg-[#008031] hover:bg-[#006e2a] text-white font-semibold text-[11px] text-center transition-colors shadow-xs"
              >
                Sign Up
              </Link>
            </div>
          </div>
        ) : (
          <div className="p-3.5 border-t border-[#E9EDE7] bg-[#FAF9F6] flex items-center justify-between">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded-full bg-[#EAF3EC] border border-[#C8E0CF] text-[#008031] font-semibold text-xs flex items-center justify-center shrink-0">
                {userInitials}
              </div>
              <div className="min-w-0">
                <div className="text-xs font-semibold text-[#1A1A1A] truncate">{user?.name || "Authenticated User"}</div>
                <div className="text-[11px] text-[#767676] truncate">{user?.email}</div>
              </div>
            </div>
            <button
              onClick={handleLogout}
              title="Sign Out"
              aria-label="Sign out"
              className="p-1.5 rounded-lg hover:bg-[#F3F2EE] text-[#767676] hover:text-red-600 transition-colors"
            >
              <LogOut className="w-4 h-4" aria-hidden="true" />
            </button>
          </div>
        )}
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Mobile Header */}
        <header className="h-16 px-6 border-b border-[#E9EDE7] bg-white flex items-center justify-between md:hidden">
          <button
            ref={mobileTriggerRef}
            onClick={() => setMobileOpen(true)}
            aria-label="Open navigation menu"
            aria-expanded={mobileOpen}
            className="p-1.5 rounded-lg border border-[#E9EDE7] text-[#555555]"
          >
            <Menu className="w-5 h-5" aria-hidden="true" />
          </button>
          <div className="font-editorial font-bold text-lg text-[#1A1A1A]">AMARACUS</div>
          {isGuest ? (
            <Link
              href={`/login?redirect=${encodeURIComponent(pathname)}`}
              className="px-2.5 py-1 rounded-md bg-[#008031] text-white text-xs font-semibold"
            >
              Sign In
            </Link>
          ) : (
            <div className="w-7 h-7 rounded-full bg-[#EAF3EC] text-[#008031] text-xs font-bold flex items-center justify-center">
              {userInitials}
            </div>
          )}
        </header>

        <main className="flex-1 p-6 md:p-10 max-w-6xl w-full mx-auto">
          {/* Guest Exploration Banner */}
          {isGuest && (
            <div className="mb-6 p-4 rounded-xl border border-[#C8E0CF] bg-[#EAF3EC] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs shadow-xs">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-white border border-[#C8E0CF] flex items-center justify-center text-[#008031] shrink-0">
                  <Shield className="w-4 h-4 fill-[#008031]/20 stroke-[#008031]" />
                </div>
                <div>
                  <div className="font-semibold text-[#1A1A1A] flex items-center gap-2">
                    <span>Guest Preview Mode</span>
                    <Badge variant="outline" className="border-[#008031] text-[#008031] bg-white text-[10px] px-1.5 py-0 font-semibold">
                      Read Only
                    </Badge>
                  </div>
                  <p className="text-[11px] text-[#636863] mt-0.5">
                    <GuestBannerText />
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0 w-full sm:w-auto">
                <Link
                  href={`/login?redirect=${encodeURIComponent(pathname)}`}
                  className="flex-1 sm:flex-none text-center px-3.5 py-1.5 rounded-lg border border-[#C8E0CF] bg-white hover:bg-[#F3F2EE] text-[#1A1A1A] text-xs font-medium transition-colors"
                >
                  Sign In
                </Link>
                <Link
                  href={`/signup?redirect=${encodeURIComponent(pathname)}`}
                  className="flex-1 sm:flex-none text-center px-3.5 py-1.5 rounded-lg bg-[#008031] hover:bg-[#006e2a] text-white text-xs font-semibold transition-colors shadow-xs"
                >
                  Create Account
                </Link>
              </div>
            </div>
          )}

          {children}
        </main>
      </div>

      {/* Create Organization Modal */}
      <Modal
        isOpen={createOrgOpen}
        onClose={() => setCreateOrgOpen(false)}
        title="Create New Organization"
        maxWidth="max-w-md"
      >
        {orgError && (
          <div className="p-3 mb-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs">
            {orgError}
          </div>
        )}

        <form onSubmit={handleCreateOrg} className="space-y-4 text-xs">
          <div className="space-y-1.5">
            <label htmlFor="new-org-name" className="font-medium text-[#1A1A1A]">
              Organization Name
            </label>
            <input
              id="new-org-name"
              type="text"
              placeholder="e.g. Apex Cryptography Group"
              value={newOrgName}
              onChange={(e) => setNewOrgName(e.target.value)}
              className="w-full px-3 py-2 border border-[#E9EDE7] rounded-lg focus:outline-none focus:border-[#008031]"
              autoFocus
              required
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setCreateOrgOpen(false)}
              className="px-4 py-2 rounded-lg border border-[#E9EDE7] font-medium text-[#555555] hover:bg-[#F8F7F4]"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={creatingOrg}
              className="px-4 py-2 rounded-lg bg-[#008031] text-white font-medium hover:bg-[#006827] flex items-center gap-1.5"
            >
              {creatingOrg ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" /> Creating...
                </>
              ) : (
                "Create Organization"
              )}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
