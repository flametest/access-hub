"use client";

import Link from "next/link";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { StatusChip } from "@/components/chips";
import { ForbiddenCard } from "@/components/page-state";
import { TableSkeleton } from "@/components/table";
import { Tabs } from "@/components/tabs";
import { Icon } from "@/components/icon";
import { AccountsTab } from "@/app/admin/apps/[appKey]/accounts-tab";
import { CustomRulesTab } from "@/app/admin/apps/[appKey]/custom-rules-tab";
import { InvitationsTab } from "@/app/admin/apps/[appKey]/invitations-tab";
import { OAuthClientsTab } from "@/app/admin/apps/[appKey]/oauth-clients-tab";
import { ResourcesTab } from "@/app/admin/apps/[appKey]/resources-tab";
import { RolesTab } from "@/app/admin/apps/[appKey]/roles-tab";
import { adminApi } from "@/lib/admin/api";
import { isForbidden } from "@/lib/api";

const TABS = [
  { key: "resources", label: "Resources", icon: "layers" as const },
  { key: "roles", label: "Roles", icon: "key" as const },
  { key: "accounts", label: "Accounts", icon: "users" as const },
  { key: "invitations", label: "Invitations", icon: "ticket" as const },
  { key: "oauth", label: "OAuth clients", icon: "lock" as const },
  { key: "rules", label: "Custom rules", icon: "settings" as const },
];

/**
 * App detail: header (identity from the apps list) + tabbed management
 * sections. The active tab lives in the ?tab= query param. Each tab handles
 * its own loading / 403 / error states (admin codes are per-section).
 */
export default function AdminAppDetailPage() {
  const router = useRouter();
  const params = useParams<{ appKey: string }>();
  const appKey = decodeURIComponent(params.appKey);
  const searchParams = useSearchParams();
  const tab = searchParams.get("tab") ?? "resources";
  const activeTab = TABS.some((item) => item.key === tab) ? tab : "resources";

  // The header uses the apps list (one cheap fetch) — org_admins can list
  // their org's apps, so this normally resolves; anything else degrades to
  // showing just the key.
  const appsQuery = useQuery({
    queryKey: ["admin", "apps"],
    queryFn: () => adminApi.listApps(),
  });
  const app = appsQuery.data?.find((item) => item.key === appKey);

  function onTabChange(key: string) {
    router.replace(`/admin/apps/${encodeURIComponent(appKey)}?tab=${key}`, {
      scroll: false,
    });
  }

  if (isForbidden(appsQuery.error)) {
    return (
      <ForbiddenCard message="You don't hold admin:app:read — org admins can manage apps of their own org." />
    );
  }

  return (
    <div>
      <Link
        href="/admin/apps"
        className="inline-flex items-center gap-1.5 text-[13px] font-bold text-white/55 transition-colors hover:text-white"
      >
        <Icon name="arrow-left" className="size-4" />
        All apps
      </Link>

      <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-2">
        <h1 className="text-2xl font-extrabold tracking-tight">
          {app?.name ?? appKey}
        </h1>
        <span className="rounded-md border border-white/15 bg-white/[0.07] px-2 py-0.5 font-mono text-[13px] text-white/70">
          {appKey}
        </span>
        {app && <StatusChip status={app.status} />}
        {app?.org_key && (
          <span className="text-[13px] text-white/50">org: {app.org_key}</span>
        )}
      </div>
      {app?.description && (
        <p className="mt-1 max-w-3xl text-sm text-white/55">{app.description}</p>
      )}

      {appsQuery.isLoading && <TableSkeleton rows={2} className="mt-6" />}

      {appsQuery.data && (
        <>
          <Tabs
            items={TABS}
            active={activeTab}
            onChange={onTabChange}
            className="mt-6"
          />
          <div className="mt-5">
            {activeTab === "resources" && <ResourcesTab appKey={appKey} />}
            {activeTab === "roles" && <RolesTab appKey={appKey} />}
            {activeTab === "accounts" && <AccountsTab appKey={appKey} />}
            {activeTab === "invitations" && <InvitationsTab appKey={appKey} />}
            {activeTab === "oauth" && <OAuthClientsTab appKey={appKey} />}
            {activeTab === "rules" && <CustomRulesTab appKey={appKey} />}
          </div>
        </>
      )}
    </div>
  );
}
