"""Toy reconciliation service. Not real code; a planting target for Snare's tests."""


def reconcile(rows):
    return sum(r["amount"] for r in rows)
