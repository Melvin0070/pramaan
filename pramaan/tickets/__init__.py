"""Ticket adapters: routes an `open_ticket` / `escalate_human` decision to a
tracker. See `pramaan.tickets.adapter`.
"""

from pramaan.tickets.adapter import (
    DevRevAdapter,
    GitHubIssuesAdapter,
    TicketAdapter,
    TicketRef,
    ticket_body,
    ticket_title,
)

__all__ = [
    "DevRevAdapter",
    "GitHubIssuesAdapter",
    "TicketAdapter",
    "TicketRef",
    "ticket_body",
    "ticket_title",
]
