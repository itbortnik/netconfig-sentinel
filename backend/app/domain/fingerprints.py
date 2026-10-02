"""Stable content identity shared by explanations and human assessment bindings."""

import json
from hashlib import sha256

from app.domain.models import Finding


def finding_fingerprint(finding: Finding) -> str:
    contents = json.dumps(finding.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return sha256(contents.encode("utf-8")).hexdigest()
