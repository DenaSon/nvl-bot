# CICD-07A — Dependency discovery and manual monitor reconciliation

## Changelog
- شناسایی خودکار وابستگی‌های پایتون بات بدون نیاز به ویرایش دستی فهرست انتشار.
- تطبیق نسخه فیلترینگ نصب‌شده با نسخه تأییدشده مخزن، پس از بررسی فایل‌ها و تایمرهای فعال.
- خروج همگام‌سازی غیرفعال Edge و ابزار بازپخش آفلاین از چرخه استقرار.

## Scope and safety
This is the first implementation increment, not a complete multi-component publisher.
The same release-plan builder is used for discovery and publisher revalidation.
The existing accepted inventory remains a compatibility seed; static root imports
and literal dynamic imports are derived from both pinned Git trees, transitively.
No candidate Python is imported. Git blob identities are verified. Shared
independent dependencies, package paths, unknown scripts, deletions and mode
changes retain the existing HOLD policy. Existing unowned files are not overwritten.
An existing baseline dependency absent from runtime is a drift, not permission to
install silently. Nonliteral dynamic imports and external command dependencies
remain outside discovery.

The already manually deployed monitor can be reconciled only when its two
Python files, alert timer, sampler override and loaded timer schedule all match.
This does not publish new monitor files. The offline replay and retired
sync entrypoint are repository-only, not executed by the publisher. Other
migration and operational scripts are still held.

## Activation
Do not auto-install the control plane from a running publisher. After review
and green master CI, use a one-time pinned control-plane upgrade under the
existing deployment lock, with the apply/observer timers quiesced. Install the
three changed ops/nvl_cd_*.py modules together with the inventory module
available in /opt/nvl-deploy. Keep the checkpoint and config unchanged.
Verify discovery, dry-run plan and reconciliation before re-enabling apply.
Do not write release-state.json manually or broaden root permissions.

## Remaining acceptance
Independent monitor publisher (durable rollback, timer verification and
read-only sample health), managed systemd and AWG component contracts,
dependencies/requirements and package handling, component-aware observer
and one-time activation on Core. No production changes in this PR.
