(function () {
	const analyticsHostname = "domaindoctor.fyi";
	const analyticsWebsiteId = "15999a2d-f021-4678-9b84-51f61b9c8f7f";
	const queuedAnalyticsEvents = [];

	function sanitizeLocation(value) {
		if (!value) {
			return value;
		}

		try {
			const parsed = new URL(value, window.location.origin);

			if (parsed.origin === window.location.origin) {
				return parsed.pathname;
			}

			return `${parsed.origin}${parsed.pathname}`;
		} catch {
			return String(value).split(/[?#]/, 1)[0];
		}
	}

	window.domainDoctorAnalyticsBeforeSend = function (type, payload) {
		if (!payload) {
			return payload;
		}

		const sanitized = { ...payload };

		if (sanitized.url) {
			sanitized.url = sanitizeLocation(sanitized.url);
		}

		if (sanitized.referrer) {
			sanitized.referrer = sanitizeLocation(sanitized.referrer);
		}

		if (window.location.pathname === "/check") {
			sanitized.title = "Diagnostic Report | Domain Doctor";
		}

		return sanitized;
	};

	function flushQueuedAnalyticsEvents() {
		if (!window.umami || typeof window.umami.track !== "function") {
			return;
		}

		while (queuedAnalyticsEvents.length > 0) {
			window.umami.track(queuedAnalyticsEvents.shift());
		}
	}

	window.trackDomainDoctorEvent = function (eventName) {
		if (window.location.hostname !== analyticsHostname) {
			return;
		}

		if (window.umami && typeof window.umami.track === "function") {
			window.umami.track(eventName);
			return;
		}

		queuedAnalyticsEvents.push(eventName);
	};

	function loadAnalytics() {
		if (window.location.hostname !== analyticsHostname) {
			return;
		}

		const script = document.createElement("script");
		script.defer = true;
		script.src = "https://cloud.umami.is/script.js";
		script.dataset.websiteId = analyticsWebsiteId;
		script.dataset.domains = analyticsHostname;
		script.dataset.excludeSearch = "true";
		script.dataset.excludeHash = "true";
		script.dataset.doNotTrack = "true";
		script.dataset.beforeSend = "domainDoctorAnalyticsBeforeSend";
		script.addEventListener("load", flushQueuedAnalyticsEvents);

		document.head.appendChild(script);
	}

	loadAnalytics();
})();

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

	document
		.querySelectorAll('a[href="https://github.com/casual-loops/domain-doctor"]')
		.forEach((element) => {
			element.addEventListener("click", () => {
				trackEvent("github-click");
			});
		});

	document.querySelectorAll('a[href="/docs"]').forEach((element) => {
		element.addEventListener("click", () => {
			trackEvent("api-docs-click");
		});
	});

	if (document.querySelector(".report-heading")) {
		trackEvent("scan-completed");
	}

	if (document.querySelector(".error-panel")) {
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

	document.querySelectorAll("[data-collapsible]").forEach((panel) => {
		const toggle = panel.querySelector("[data-collapsible-toggle]");
		const content = panel.querySelector("[data-collapsible-content]");
		const icon = panel.querySelector(".redirect-toggle");

		if (!toggle || !content) {
			return;
		}

		toggle.addEventListener("click", () => {
			const isExpanded = toggle.getAttribute("aria-expanded") === "true";

			if (isExpanded) {
				content.style.height = `${content.scrollHeight}px`;

				requestAnimationFrame(() => {
					content.style.height = "0px";
					content.style.opacity = "0";
				});

				panel.classList.add("is-collapsed");
				toggle.setAttribute("aria-expanded", "false");

				if (icon) {
					icon.textContent = "+";
				}

				return;
			}

			panel.classList.remove("is-collapsed");
			content.style.height = `${content.scrollHeight}px`;
			content.style.opacity = "1";
			toggle.setAttribute("aria-expanded", "true");

			if (icon) {
				icon.textContent = "−";
			}

			content.addEventListener(
				"transitionend",
				() => {
					content.style.height = "auto";
				},
				{ once: true },
			);
		});
	});

	const reducedMotion = window.matchMedia(
		"(prefers-reduced-motion: reduce)",
	).matches;

	document.querySelectorAll(".result-details").forEach((details) => {
		const summary = details.querySelector("summary");

		if (!summary) {
			return;
		}

		let isAnimating = false;

		summary.addEventListener("click", (event) => {
			if (reducedMotion) {
				return;
			}

			event.preventDefault();

			if (isAnimating) {
				return;
			}

			isAnimating = true;

			if (details.open) {
				const startHeight = details.offsetHeight;
				const endHeight = summary.offsetHeight;

				details.classList.add("is-closing");
				details.style.height = `${startHeight}px`;

				requestAnimationFrame(() => {
					details.style.height = `${endHeight}px`;
				});

				details.addEventListener(
					"transitionend",
					(event) => {
						if (event.propertyName !== "height") {
							return;
						}

						details.open = false;
						details.classList.remove("is-closing");
						details.style.height = "";
						isAnimating = false;
					},
					{ once: true },
				);

				return;
			}

			const startHeight = details.offsetHeight;

			details.open = true;

			const endHeight = details.offsetHeight;

			details.classList.add("is-opening");
			details.style.height = `${startHeight}px`;

			requestAnimationFrame(() => {
				details.style.height = `${endHeight}px`;
			});

			details.addEventListener(
				"transitionend",
				(event) => {
					if (event.propertyName !== "height") {
						return;
					}

					details.classList.remove("is-opening");
					details.style.height = "";
					isAnimating = false;
				},
				{ once: true },
			);
		});
	});
});
