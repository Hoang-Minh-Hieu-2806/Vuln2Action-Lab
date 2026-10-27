"""Reference metadata extraction; this module never downloads exploit code."""

from vuln2action.domain import CveRecord, ExploitReference


def references_from_cve(cve: CveRecord) -> list[ExploitReference]:
    return [ExploitReference(url=url) for url in cve.references]
