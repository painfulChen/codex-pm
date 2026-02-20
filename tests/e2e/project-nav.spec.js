const { test, expect } = require("@playwright/test");

function buildProjectData(names) {
  const items = names.map((name, idx) => ({
    id: `task-${idx + 1}`,
    text: `Task for ${name}`,
    status: idx % 3 === 0 ? "doing" : "todo",
    priority: "P1",
    project: name,
    createdAt: `2026-02-${String((idx % 20) + 1).padStart(2, "0")}T10:00:00+08:00`,
    updatedAt: `2026-02-${String((idx % 20) + 1).padStart(2, "0")}T10:00:00+08:00`,
  }));
  const iterLatestByProject = {};
  names.forEach((name, idx) => {
    const day = String(28 - (idx % 27)).padStart(2, "0");
    iterLatestByProject[name] = `2026-02-${day}T12:00:00+08:00`;
  });
  return { items, iterLatestByProject };
}

async function mockPmApis(page, options = {}) {
  const projects = Array.isArray(options.projects) ? options.projects : ["coach-feishu-suite"];
  const featureFlags = {
    projectTabsPagination: true,
    projectTabsGrouping: true,
    projectTabsBadges: true,
    projectTabsSearch: true,
    projectTabsPageThreshold: 80,
    projectTabsPageSize: 40,
    ...(options.featureFlags || {}),
  };
  const base = buildProjectData(projects);
  let config = {
    version: 1,
    updatedAt: "2026-02-19T12:00:00+08:00",
    uiPrefs: options.uiPrefs || {},
    featureFlags,
    telemetry: { enabled: true, localOnly: true, allowSend: false, endpoint: "" },
    subscription: {
      licenseKey: "",
      status: "inactive",
      tier: "free",
      activation: { mode: "offline", cloudStatus: "inactive" },
    },
  };

  await page.route("**/api/**", async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();
    const url = new URL(req.url());
    const path = url.pathname;
    let body = {};
    try {
      body = req.postDataJSON() || {};
    } catch (_) {
      body = {};
    }
    const json = (payload) =>
      route.fulfill({
        status: 200,
        contentType: "application/json; charset=utf-8",
        body: JSON.stringify(payload),
      });

    if (path === "/api/todos") {
      return json({
        ok: true,
        data: { version: 1, updatedAt: "2026-02-19T12:00:00+08:00", items: base.items, agents: {} },
        projects,
        defaultProject: projects[0] || "coach-feishu-suite",
        iterLatestByProject: base.iterLatestByProject,
        iterUpdatedAt: "2026-02-19T12:00:00+08:00",
        uiPrefs: config.uiPrefs,
        featureFlags: config.featureFlags,
      });
    }
    if (path === "/api/config") {
      if (method === "POST") {
        if (body.action === "set_ui_prefs" && body.prefs && typeof body.prefs === "object") {
          config = { ...config, uiPrefs: { ...config.uiPrefs, ...body.prefs }, updatedAt: new Date().toISOString() };
        } else if (body.action === "set_feature_flags" && body.flags && typeof body.flags === "object") {
          config = { ...config, featureFlags: { ...config.featureFlags, ...body.flags }, updatedAt: new Date().toISOString() };
        }
      }
      return json({ ok: true, data: config });
    }
    if (path === "/api/telemetry") {
      return json({ ok: true, data: { count: 0, events: [] } });
    }
    if (path === "/api/services") {
      return json({ ok: true, data: { checkedAt: "2026-02-19T12:00:00+08:00", groups: [] } });
    }
    if (path === "/api/project-doc") {
      return json({ ok: true, data: { project: projects[0] || "coach-feishu-suite", content: "# Doc" } });
    }
    if (path === "/api/iterations") {
      return json({ ok: true, data: { items: [] }, defaultProject: projects[0] || "coach-feishu-suite" });
    }
    return json({ ok: true, data: {} });
  });
}

test("按最近时间降序 + 收藏置顶 + 刷新后保留选择", async ({ page }) => {
  await mockPmApis(page, {
    projects: ["alpha", "beta", "gamma"],
    uiPrefs: { projectFavorites: [] },
  });

  await page.goto("/pm");
  await expect(page.locator('[data-project-value="__all__"]')).toBeVisible();

  const before = await page.evaluate(() =>
    Array.from(document.querySelectorAll(".project-pill[data-project-value]"))
      .map((el) => el.getAttribute("data-project-value"))
      .filter((v) => v && v !== "__all__")
  );
  expect(before[0]).toBe("alpha");

  await page.click('[data-project-favorite="gamma"]');
  await expect(page.locator('[data-project-value="gamma"]').first()).toBeVisible();

  const after = await page.evaluate(() =>
    Array.from(document.querySelectorAll(".project-pill[data-project-value]"))
      .map((el) => el.getAttribute("data-project-value"))
      .filter((v) => v && v !== "__all__")
  );
  expect(after[0]).toBe("gamma");

  await page.evaluate(() => {
    localStorage.setItem("pm_selected_project", "beta");
    // URL project query has higher priority than localStorage; clear it to verify local restore path.
    history.replaceState(null, "", "/pm");
  });
  await page.reload();
  await expect(page.locator("#projectFilter")).toHaveValue("beta");
});

test("项目导航支持 Arrow + Home/End + Enter 键盘切换", async ({ page }) => {
  await mockPmApis(page, {
    projects: ["app-a", "app-b", "app-c", "app-d"],
  });
  await page.goto("/pm");
  await expect(page.locator('[data-project-value="__all__"]')).toBeVisible();

  const allPill = page.locator('.project-pill[data-project-value="__all__"]');
  await allPill.focus();
  await page.keyboard.press("ArrowRight");
  await page.keyboard.press("Enter");
  await expect(page.locator("#projectFilter")).toHaveValue("app-a");

  await page.locator('.project-pill.active[data-project-value="app-a"]').focus();
  const expectedLast = await page.evaluate(() => {
    const pills = Array.from(document.querySelectorAll(".project-pill[data-project-value]"));
    const last = pills[pills.length - 1];
    return last ? String(last.getAttribute("data-project-value") || "") : "";
  });
  await page.keyboard.press("End");
  await page.keyboard.press("Enter");
  await expect(page.locator("#projectFilter")).toHaveValue(expectedLast);

  await page.locator(`.project-pill.active[data-project-value="${expectedLast}"]`).focus();
  await page.keyboard.press("Home");
  await page.keyboard.press("Enter");
  await expect(page.locator("#projectFilter")).toHaveValue("__all__");
});

test("项目很多时分页可用且可通过搜索跳转", async ({ page }) => {
  const projects = Array.from({ length: 95 }, (_, i) => `project-${String(i + 1).padStart(3, "0")}`);
  await mockPmApis(page, {
    projects,
    featureFlags: {
      projectTabsPagination: true,
      projectTabsPageThreshold: 20,
      projectTabsPageSize: 10,
      projectTabsSearch: true,
    },
  });
  await page.goto("/pm");
  await expect(page.locator("#projectTabsPager")).toHaveText("1/10");
  await expect(page.locator("#projectTabsPageNext")).toBeEnabled();

  await page.click("#projectSearchBtn");
  await expect(page.locator("#projectSearchModal")).toHaveClass(/show/);
  await page.fill("#projectSearchInput", "project-094");
  await page.keyboard.press("Enter");
  await expect(page.locator("#projectFilter")).toHaveValue("project-094");
});
