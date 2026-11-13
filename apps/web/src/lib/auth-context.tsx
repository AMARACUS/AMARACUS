'use client';

import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { api } from './api-client';
import { AuthRequiredModal } from '@/components/auth-required-modal';

export interface User {
  id: string;
  email: string;
  name?: string | null;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  role: 'OWNER' | 'ADMIN' | 'MEMBER';
}

interface AuthContextValue {
  user: User | null;
  activeOrg: Organization | null;
  organizations: Organization[];
  loading: boolean;
  isGuest: boolean;
  requireAuth: (actionName?: string) => boolean;
  openAuthModal: (actionName?: string) => void;
  closeAuthModal: () => void;
  login: (credentials: { email: string; password: string }) => Promise<void>;
  signup: (data: { email: string; password: string; name?: string; organizationName?: string; termsAccepted?: boolean; marketingOptIn?: boolean; ageAttested?: boolean }) => Promise<void>;
  sendSignupOtp: (data: { email: string; password: string; name?: string; organizationName?: string; termsAccepted?: boolean; marketingOptIn?: boolean; ageAttested?: boolean }) => Promise<{ success: boolean; message: string; devOtp?: string; simulated?: boolean }>;
  verifySignupOtp: (data: { email: string; otp: string }) => Promise<void>;
  resendSignupOtp: (email: string) => Promise<{ success: boolean; message: string; devOtp?: string }>;
  logout: () => Promise<void>;
  switchOrg: (orgId: string) => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [activeOrg, setActiveOrg] = useState<Organization | null>(null);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchIdentity = useCallback(async () => {
    try {
      const token = api.getAuthToken();

      if (token) {
        const data = await api.auth.me();
        if (data && data.user) {
          setUser(data.user);
          setActiveOrg(data.activeOrganization);
          setOrganizations(data.organizations || []);
          return;
        }
      }

      setUser(null);
      setActiveOrg(null);
      setOrganizations([]);
      api.setAuthToken(null);
    } catch (error) {
      setUser(null);
      setActiveOrg(null);
      setOrganizations([]);
      // Only a 401 means the session is gone. A network error, cold start or 5xx
      // keeps the token so the next load signs the user back in.
      if ((error as any)?.status === 401) {
        api.setAuthToken(null);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIdentity();
  }, [fetchIdentity]);

  const login = async (credentials: { email: string; password: string }) => {
    setLoading(true);
    try {
      const data = await api.auth.signin(credentials);
      api.setAuthToken(data.session.token);
      setUser(data.user);
      setActiveOrg(data.activeOrganization);
      setOrganizations(data.organizations || []);
    } finally {
      setLoading(false);
    }
  };

  const signup = async (payload: { email: string; password: string; name?: string; organizationName?: string; termsAccepted?: boolean; marketingOptIn?: boolean; ageAttested?: boolean }) => {
    setLoading(true);
    try {
      const data = await api.auth.signup(payload);
      api.setAuthToken(data.session.token);
      setUser(data.user);
      setActiveOrg(data.activeOrganization);
      setOrganizations([data.activeOrganization]);
    } finally {
      setLoading(false);
    }
  };

  const sendSignupOtp = async (payload: { email: string; password: string; name?: string; organizationName?: string; termsAccepted?: boolean; marketingOptIn?: boolean; ageAttested?: boolean }) => {
    return await api.auth.sendSignupOtp(payload);
  };

  const verifySignupOtp = async (payload: { email: string; otp: string }) => {
    setLoading(true);
    try {
      const data = await api.auth.verifySignupOtp(payload);
      api.setAuthToken(data.session.token);
      setUser(data.user);
      setActiveOrg(data.activeOrganization);
      setOrganizations([data.activeOrganization]);
    } finally {
      setLoading(false);
    }
  };

  const resendSignupOtp = async (email: string) => {
    return await api.auth.resendSignupOtp({ email });
  };

  const logout = async () => {
    setLoading(true);
    try {
      await api.auth.signout();
    } catch {
      // Ignore network errors on signout
    }
    try {
      // Nothing else to clear: the API session is the only session.
    } finally {
      api.setAuthToken(null);
      setUser(null);
      setActiveOrg(null);
      setOrganizations([]);
      setLoading(false);
    }
  };

  const switchOrg = async (orgId: string) => {
    const data = await api.organizations.switch(orgId);
    if (data.activeOrganization) {
      setActiveOrg(data.activeOrganization);
    }
    await fetchIdentity();
  };

  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authModalAction, setAuthModalAction] = useState<string>("perform this action");

  const requireAuth = useCallback((actionName?: string): boolean => {
    if (user) return true;
    setAuthModalAction(actionName || "perform this action");
    setAuthModalOpen(true);
    return false;
  }, [user]);

  const openAuthModal = useCallback((actionName?: string) => {
    setAuthModalAction(actionName || "perform this action");
    setAuthModalOpen(true);
  }, []);

  const closeAuthModal = useCallback(() => {
    setAuthModalOpen(false);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        activeOrg,
        organizations,
        loading,
        isGuest: !loading && !user,
        requireAuth,
        openAuthModal,
        closeAuthModal,
        login,
        signup,
        sendSignupOtp,
        verifySignupOtp,
        resendSignupOtp,
        logout,
        switchOrg,
        refresh: fetchIdentity,
      }}
    >
      {children}
      <AuthRequiredModal
        isOpen={authModalOpen}
        onClose={closeAuthModal}
        actionName={authModalAction}
      />
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
