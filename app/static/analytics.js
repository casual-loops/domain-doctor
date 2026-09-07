(function () {
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

	window.trackDomainDoctorEvent = function (eventName) {
		if (window.umami && typeof window.umami.track === "function") {
			window.umami.track(eventName);
		}
	};
})();
