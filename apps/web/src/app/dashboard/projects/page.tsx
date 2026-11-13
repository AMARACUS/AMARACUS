"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Modal } from "@/components/ui/modal";
import { Plus, Database, AlertCircle, CheckCircle2, Loader2, Trash2 } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import Link from "next/link";
import { api } from "@/lib/api-client";
import { sanitizeText } from "@/lib/sanitize";
import {
  ProjectLimitUpgradeModal,
  resolveProjectLimitUpgrade,
  type ProjectLimitUpgradeInfo,
} from "@/components/cloud/project-limit-upgrade-modal";

export interface ProjectEnvironment {
  id: string;
  name: string;
  slug: string;
  type: string;
}

export interface ProjectItem {
  id: string;
  organizationId: string;
  name: string;
  slug: string;
  description?: string | null;
  environments?: ProjectEnvironment[];
  createdAt: string;
}

export default function ProjectsPage() {
  const { activeOrg, requireAuth, user } = useAuth();
  const [projects, setProjects] = useState<ProjectItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const [isModalOpen, setIsModalOpen] = useState(false);

  // Form State
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [description, setDescription] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);

  // Submission State
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);
  // Kept apart from formSuccess, which locks the form: this one leaves it ready to submit.
  const [planNotice, setPlanNotice] = useState<string | null>(null);

  // Upgrade Modal State for Resource Limits (e.g. 2nd project on Free)
  const [isUpgradeModalOpen, setIsUpgradeModalOpen] = useState(false);
  const [limitUpgrade, setLimitUpgrade] = useState<ProjectLimitUpgradeInfo | null>(null);

  const [deletingId, setDeletingId] = useState<string | null>(null);

  const fetchProjects = useCallback(async () => {
    if (!activeOrg) {
      setProjects([
        {
          id: "demo-project-preview",
          organizationId: "demo-org",
          name: "Sample Cryptographic Service (Preview)",
          slug: "sample-crypto-service",
          description: "Preview project demonstrating cryptographic environment topology and key lifecycle bindings.",
          environments: [
            { id: "demo-env-1", name: "Production", slug: "production", type: "production" },
            { id: "demo-env-2", name: "Staging", slug: "staging", type: "staging" },
            { id: "demo-env-3", name: "Development", slug: "development", type: "development" },
          ],
          createdAt: new Date().toISOString(),
        },
      ]);
      setLoading(false);
      return;
    }
    setLoading(true);
    setFetchError(null);
    try {
      const data = await api.projects.list(activeOrg.id);
      setProjects(data.projects || []);
    } catch (err: any) {
      setFetchError(err.message || "Failed to load projects.");
    } finally {
      setLoading(false);
    }
  }, [activeOrg]);

  useEffect(() => {
    fetchProjects();
  }, [fetchProjects]);

  const handleNameChange = (val: string) => {
    setName(val);
    if (!slugTouched) {
      setSlug(
        val
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/^-+|-+$/g, "")
      );
    }
  };

  const handleOpenModal = () => {
    if (!requireAuth("create a new project")) return;
    setName("");
    setSlug("");
    setDescription("");
    setSlugTouched(false);
    setFormError(null);
    setFormSuccess(null);
    setPlanNotice(null);
    setIsModalOpen(true);
  };

  const handleCloseModal = () => {
    if (submitting) return;
    setIsModalOpen(false);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setFormSuccess(null);
    setPlanNotice(null);

    if (!activeOrg) {
      setFormError("No active organization selected.");
      return;
    }

    const safeName = sanitizeText(name);
    const trimmedSlug = slug.trim().toLowerCase();
    const safeDesc = description.trim() ? sanitizeText(description, { allowMultiline: true }) : undefined;

    if (!safeName) {
      setFormError("Project name is required.");
      return;
    }
    if (safeName.length < 3) {
      setFormError("Project name must be at least 3 characters.");
      return;
    }
    if (!trimmedSlug) {
      setFormError("Project slug is required.");
      return;
    }
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(trimmedSlug)) {
      setFormError("Slug can only contain lowercase letters, numbers, and hyphens.");
      return;
    }

    setSubmitting(true);
    try {
      const res = await api.projects.create(activeOrg.id, {
        name: safeName,
        slug: trimmedSlug,
        description: safeDesc,
      });

      setFormSuccess(`Project "${safeName}" created with default environments.`);
      await fetchProjects();

      setTimeout(() => {
        setIsModalOpen(false);
      }, 700);
    } catch (err: any) {
      if (err.code === 'PROJECT_LIMIT_REACHED' || err.message?.toLowerCase().includes('limit reached')) {
        // Project limit reached: close the creation modal and offer the next plan up.
        const upgrade = await resolveProjectLimitUpgrade(err, activeOrg.id, projects.length);
        if (upgrade) {
          setIsModalOpen(false);
          setLimitUpgrade(upgrade);
          setIsUpgradeModalOpen(true);
        } else {
          setFormError(err.message || "Project limit reached. Upgrade your plan to create more projects.");
        }
      } else {
        setFormError(err.message || "Failed to create project.");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteProject = async (projectId: string) => {
    if (!requireAuth("delete projects")) return;
    if (!activeOrg) return;
    if (!confirm("Are you sure you want to delete this project and all its environments?")) return;
    setDeletingId(projectId);
    try {
      await api.projects.delete(activeOrg.id, projectId);
      await fetchProjects();
    } catch (err: any) {
      alert(err.message || "Failed to delete project.");
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E9EDE7] pb-6">
        <div>
          <h1 className="font-editorial text-3xl md:text-4xl font-bold text-[#1A1A1A] tracking-tight">
            Projects & Environments
          </h1>
          <p className="text-sm text-[#636863] mt-1.5 leading-relaxed">
            Organize cryptographic keys, policies, and credentials into isolated domains for{" "}
            <span className="font-medium text-[#1A1A1A]">{activeOrg?.name || "your workspace"}</span>.
          </p>
        </div>
        <Button onClick={handleOpenModal} className="shrink-0">
          <Plus className="w-4 h-4 mr-1.5" /> Create Project
        </Button>
      </div>

      {fetchError && (
        <div className="p-4 rounded-xl border border-red-200 bg-red-50 text-red-700 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{fetchError}</span>
        </div>
      )}

      {/* Loading State */}
      {loading ? (
        <div className="py-20 flex flex-col items-center justify-center text-[#767676]">
          <Loader2 className="w-6 h-6 animate-spin text-[#008031] mb-2" />
          <span className="text-xs">Loading projects from persistence layer...</span>
        </div>
      ) : projects.length === 0 ? (
        /* Empty State */
        <div className="p-12 text-center border border-dashed border-[#E9EDE7] rounded-2xl bg-white space-y-4">
          <div className="w-12 h-12 rounded-2xl bg-[#EAF3EC] text-[#008031] flex items-center justify-center mx-auto">
            <Database className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-[#1A1A1A]">No projects found</h3>
            <p className="text-xs text-[#767676] max-w-sm mx-auto mt-1">
              Create your first project to provision production, staging, and development cryptographic boundaries.
            </p>
          </div>
          <Button onClick={handleOpenModal} size="sm">
            <Plus className="w-3.5 h-3.5 mr-1" /> Create Project
          </Button>
        </div>
      ) : (
        /* Projects Grid */
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map((proj) => {
            const envs = proj.environments || [];
            return (
              <Card key={proj.id} className="hover:border-[#008031] transition-all duration-200 flex flex-col justify-between">
                <CardHeader>
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div className="w-9 h-9 rounded-lg bg-[#EAF3EC] border border-[#C8E0CF] flex items-center justify-center text-[#008031] shrink-0">
                      <Database className="w-4 h-4" />
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Badge variant="default">{envs.length} Environments</Badge>
                      <button
                        onClick={() => handleDeleteProject(proj.id)}
                        disabled={deletingId === proj.id}
                        title="Delete project"
                        aria-label={`Delete project ${proj.name}`}
                        className="p-1 rounded text-[#767676] hover:text-red-600 hover:bg-red-50 transition-colors"
                      >
                        {deletingId === proj.id ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                        ) : (
                          <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                        )}
                      </button>
                    </div>
                  </div>
                  <CardTitle className="text-lg font-semibold text-[#1A1A1A]">{proj.name}</CardTitle>
                  <div className="font-mono text-xs text-[#767676]">{proj.slug}</div>
                  <CardDescription className="text-xs text-[#636863] mt-2 line-clamp-2">
                    {proj.description || "Isolated cryptographic project domain."}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-2.5 pt-0 text-xs">
                  <div className="border-t border-[#E9EDE7] pt-3 space-y-2">
                    {envs.length > 0 ? (
                      envs.map((env) => (
                        <div key={env.id} className="flex items-center justify-between p-2.5 rounded-lg bg-[#FAF9F6] border border-[#E9EDE7]">
                          <div>
                            <div className="font-medium text-[#1A1A1A] capitalize">{env.name}</div>
                            <div className="text-[11px] text-[#767676] font-mono">{env.type}</div>
                          </div>
                          <span className="w-2 h-2 rounded-full bg-[#008031]" title="Operational">
                            <span className="sr-only">Operational status</span>
                          </span>
                        </div>
                      ))
                    ) : (
                      <div className="text-[11px] text-[#767676] italic">No environments created</div>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Create Project Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={handleCloseModal}
        title="Create New Project"
        description="Provision an isolated domain with Production, Staging, and Development environments."
      >
        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          {formError && (
            <div className="p-3 rounded-lg border border-red-200 bg-red-50 text-red-700 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{formError}</span>
            </div>
          )}

          {formSuccess && (
            <div className="p-3 rounded-lg border border-[#C8E0CF] bg-[#EAF3EC] text-[#008031] flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{formSuccess}</span>
            </div>
          )}

          {planNotice && (
            <div className="p-3 rounded-lg border border-[#C8E0CF] bg-[#EAF3EC] text-[#008031] flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{planNotice}</span>
            </div>
          )}

          <div>
            <label className="font-medium text-[#1A1A1A] block mb-1.5">
              Project Name <span className="text-red-500">*</span>
            </label>
            <Input
              placeholder="e.g. Settlement Engine"
              value={name}
              onChange={(e) => handleNameChange(e.target.value)}
              disabled={submitting || !!formSuccess}
              required
            />
          </div>

          <div>
            <label className="font-medium text-[#1A1A1A] block mb-1.5">
              Project Identifier / Slug <span className="text-red-500">*</span>
            </label>
            <Input
              placeholder="e.g. settlement-engine"
              value={slug}
              onChange={(e) => {
                setSlugTouched(true);
                setSlug(e.target.value);
              }}
              disabled={submitting || !!formSuccess}
              className="font-mono"
              required
            />
            <span className="text-[11px] text-[#767676] mt-1 block">
              Used in scoped API keys and cryptographic routing. Lowercase letters, numbers, and hyphens.
            </span>
          </div>

          <div>
            <label htmlFor="project-description" className="font-medium text-[#1A1A1A] block mb-1.5">Description</label>
            <textarea
              id="project-description"
              rows={3}
              placeholder="Brief description of the cryptographic workloads isolated in this project..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              disabled={submitting || !!formSuccess}
              className="w-full rounded-lg border border-[#E9EDE7] bg-white p-3 text-xs text-[#1A1A1A] focus:border-[#008031] focus:outline-none"
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleCloseModal}
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              size="sm"
              disabled={submitting || !!formSuccess}
            >
              {submitting ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Creating...
                </>
              ) : (
                "Create Project"
              )}
            </Button>
          </div>
        </form>
      </Modal>

      {/* AMARACUS Cloud only: project limit upgrade offer (renders nothing when self-hosted) */}
      <ProjectLimitUpgradeModal
        limitUpgrade={limitUpgrade}
        isOpen={isUpgradeModalOpen}
        onClose={() => {
          setIsUpgradeModalOpen(false);
          setLimitUpgrade(null);
        }}
        onPlanActivated={(planName) => {
          setIsUpgradeModalOpen(false);
          setLimitUpgrade(null);
          setFormError(null);
          setPlanNotice(`Payment verified. Your ${planName} plan is now active, so you can create this project.`);
          setIsModalOpen(true);
        }}
      />
    </div>
  );
}
