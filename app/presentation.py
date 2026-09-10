from dataclasses import dataclass
from urllib.parse import urlsplit

from app.checks.http import HttpTrace, ResponseSnapshot


@dataclass(frozen=True)
class RedirectChange:
    label: str
    kind: str


@dataclass(frozen=True)
class RedirectHopView:
    response: ResponseSnapshot
    changes: tuple[RedirectChange, ...] = ()


def build_redirect_hops(trace: HttpTrace) -> list[RedirectHopView]:
    """Build presentation data for a redirect trace."""

    hops = []

    for index, response in enumerate(trace.responses):
        changes = []

        if index < len(trace.responses) - 1:
            current = urlsplit(response.url)
            next_response = trace.responses[index + 1]
            destination = urlsplit(next_response.url)

            if current.scheme != destination.scheme:
                if current.scheme == "http" and destination.scheme == "https":
                    changes.append(
                        RedirectChange(
                            label="SCHEME UPGRADE",
                            kind="upgrade",
                        )
                    )
                elif current.scheme == "https" and destination.scheme == "http":
                    changes.append(
                        RedirectChange(
                            label="SCHEME DOWNGRADE",
                            kind="downgrade",
                        )
                    )
                else:
                    changes.append(
                        RedirectChange(
                            label="SCHEME CHANGE",
                            kind="scheme",
                        )
                    )

            current_hostname = (current.hostname or "").lower()
            destination_hostname = (destination.hostname or "").lower()

            if current_hostname != destination_hostname:
                changes.append(
                    RedirectChange(
                        label="HOSTNAME CHANGE",
                        kind="hostname",
                    )
                )

        hops.append(
            RedirectHopView(
                response=response,
                changes=tuple(changes),
            )
        )

    return hops
