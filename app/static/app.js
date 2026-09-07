document.addEventListener("DOMContentLoaded", () => {
	const overlay = document.querySelector("[data-loading-overlay]");
	const stage = document.querySelector("[data-loading-stage]");
	const forms = document.querySelectorAll("[data-diagnostic-form]");

	const stages = [
		"Resolving DNS...",
		"Inspecting TLS...",
		"Checking HTTPS behavior...",
		"Reviewing security headers...",
		"Building diagnostic report...",
	];

	const root = document.documentElement;
	const themeToggle = document.querySelector("[data-theme-toggle]");
	const themeIcon = document.querySelector("[data-theme-icon]");
	const themeLabel = document.querySelector("[data-theme-label]");
	const themeColorMeta = document.querySelector('meta[name="theme-color"]');

	const savedTheme = localStorage.getItem("domain-doctor-theme");

	const systemTheme = window.matchMedia("(prefers-color-scheme: light)").matches
		? "light"
		: "dark";

	const initialTheme = savedTheme || systemTheme;

	function trackEvent(eventName) {
		if (typeof window.trackDomainDoctorEvent === "function") {
			window.trackDomainDoctorEvent(eventName);
		}
	}

	function applyTheme(theme) {
		root.dataset.theme = theme;

		if (themeIcon) {
			themeIcon.textContent = theme === "dark" ? "☼" : "☾";
		}

		if (themeLabel) {
			themeLabel.textContent = theme === "dark" ? "Light" : "Dark";
		}

		if (themeColorMeta) {
			themeColorMeta.setAttribute(
				"content",
				theme === "dark" ? "#0a0c0f" : "#f4f5f7",
			);
		}
	}

	applyTheme(initialTheme);

	if (themeToggle) {
		themeToggle.addEventListener("click", () => {
			const nextTheme = root.dataset.theme === "dark" ? "light" : "dark";

			localStorage.setItem("domain-doctor-theme", nextTheme);

			applyTheme(nextTheme);
		});
	}

	forms.forEach((form) => {
		form.addEventListener("submit", () => {
			trackEvent("scan-started");

			if (!overlay || !stage) {
				return;
			}

			overlay.classList.add("active");
			overlay.setAttribute("aria-hidden", "false");

			let index = 0;
			stage.textContent = stages[index];

			window.setInterval(() => {
				index = Math.min(index + 1, stages.length - 1);

				stage.textContent = stages[index];
			}, 650);
		});
	});

	const hostnameInput = document.querySelector("#host");

	document.querySelectorAll("[data-host]").forEach((button) => {
		button.addEventListener("click", () => {
			if (!hostnameInput) {
				return;
			}

			hostnameInput.value = button.dataset.host;
			hostnameInput.focus();
		});
	});

	document.querySelectorAll("[data-analytics-event]").forEach((element) => {
		element.addEventListener("click", () => {
			trackEvent(element.dataset.analyticsEvent);
		});
	});

	if (document.body.dataset.scanOutcome === "completed") {
		trackEvent("scan-completed");
	}

	if (document.body.dataset.scanOutcome === "blocked") {
		trackEvent("scan-blocked");
	}

	const filterButtons = document.querySelectorAll("[data-status-filter]");

	const resultRows = document.querySelectorAll("[data-result-status]");

	const resultGroups = document.querySelectorAll("[data-result-group]");

	filterButtons.forEach((button) => {
		button.addEventListener("click", () => {
			const selectedStatus = button.dataset.statusFilter;

			filterButtons.forEach((candidate) => {
				const isActive = candidate === button;

				candidate.classList.toggle("active", isActive);

				candidate.setAttribute("aria-pressed", isActive ? "true" : "false");
			});

			resultRows.forEach((row) => {
				const shouldShow =
					selectedStatus === "all" ||
					row.dataset.resultStatus === selectedStatus;

				row.hidden = !shouldShow;
			});

			resultGroups.forEach((group) => {
				const rows = group.querySelectorAll("[data-result-status]");

				const visibleRows = Array.from(rows).filter((row) => !row.hidden);

				const emptyMessage = group.querySelector("[data-no-results]");

				if (emptyMessage) {
					emptyMessage.hidden = visibleRows.length !== 0;
				}
			});
		});
	});
});
